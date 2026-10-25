package com.webtoapp.core.pwa

import com.webtoapp.core.dns.EchConfigResolver
import com.webtoapp.core.logging.AppLogger
import com.webtoapp.core.webview.CertificateHostnameMatcher
import com.webtoapp.core.webview.ConscryptEchForwarder
import com.webtoapp.core.webview.TlsUpstreamConnector
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.conscrypt.Conscrypt
import org.conscrypt.EchRejectedException
import java.io.BufferedInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Locale
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

/**
 * ECH-capable HTTPS GET for the host's own direct fetches (site analysis,
 * icon download) on the create page.
 *
 * Why a separate client instead of reusing [ConscryptEchForwarder]: the
 * forwarder is a per-request socket writer for the MITM bridge — it streams
 * a re-framed response onto a bridge sink and reads its DoH endpoint from
 * bridge-global state set by `start()`. No bridge is running during
 * create-page analysis, and analysis needs a parsed (status, headers, body)
 * result, not a sink stream. This client therefore takes the DoH endpoint as
 * a parameter (the in-progress app's [com.webtoapp.data.model.DnsConfig]) and
 * returns a parsed result.
 *
 * The TLS setup mirrors the forwarder's (same provider registration, same
 * [ConscryptEchForwarder.EchPolicyTrustManager], same hostname check) so the
 * two legs stay behaviorally identical; the forwarder file is the reference
 * if this sequence ever changes.
 *
 * Policy, same as the forwarder: this client only runs when the host
 * publishes an ECHConfig. When it runs, the policy is REQUIRED — an
 * ECH rejection fails the fetch ([Result.Failed] with `echRejected`) instead
 * of falling back to a plaintext SNI. When the host publishes no config, or
 * DoH itself is unreachable so no config can be known, the client reports
 * [Result.NotApplicable] and the caller keeps its existing plain fetch
 * (today's behavior, unchanged). Trust comes from the system store only;
 * per-app custom CA anchors stay a bridge-only feature.
 *
 * Blocking socket IO: call only from a worker thread (PWA analysis already
 * runs on Dispatchers.IO).
 */
object EchHttpFetcher {

    private const val TAG = "EchHttpFetcher"
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 20_000
    private const val MAX_CONNECT_ATTEMPTS = 2
    private const val MAX_REDIRECTS = 5
    private const val MAX_BODY_BYTES = 2 * 1024 * 1024

    sealed interface Result {
        data class Success(
            val statusCode: Int,
            val headers: List<Pair<String, String>>,
            val body: ByteArray
        ) : Result

        /** ECH cannot run for this URL (not HTTPS, or no published ECHConfig). */
        data object NotApplicable : Result

        data class Failed(
            val message: String,
            val echRejected: Boolean = false
        ) : Result
    }

    fun fetch(
        url: String,
        dohUrl: String,
        headers: List<Pair<String, String>>
    ): Result {
        if (dohUrl.isBlank()) return Result.NotApplicable
        if (!ensureProvider()) {
            return Result.Failed("ECH 未就绪：Conscrypt 未能注册")
        }
        var currentUrl = url.toHttpUrlOrNull() ?: return Result.NotApplicable
        if (!currentUrl.isHttps) return Result.NotApplicable

        repeat(MAX_REDIRECTS + 1) {
            val host = currentUrl.host
            val port = currentUrl.port
            val records = EchConfigResolver.resolve(dohUrl, host)
            val echConfigList = records.echConfigList
            if (echConfigList == null) {
                // No published config (or DoH unreachable): ECH cannot run.
                AppLogger.d(TAG, "ECH fetch not applicable for $host (no ECHConfig)")
                return Result.NotApplicable
            }
            val addresses = records.addresses.ifEmpty {
                try {
                    InetAddress.getAllByName(host).toList()
                } catch (e: Exception) {
                    AppLogger.w(TAG, "ECH fetch: system DNS fallback failed for $host: ${e.message}")
                    emptyList()
                }
            }
            if (addresses.isEmpty()) {
                return Result.Failed("无法解析站点地址")
            }

            val socket = try {
                openTlsConnection(host, port, addresses, echConfigList)
            } catch (e: EchRejectedException) {
                AppLogger.w(TAG, "ECH rejected by $host (policy REQUIRED; not retrying plaintext): ${e.message}")
                return Result.Failed("站点拒绝了 ECH 握手", echRejected = true)
            } catch (e: Exception) {
                AppLogger.w(TAG, "ECH fetch connect failed for $host: ${e.message}")
                return Result.Failed("无法访问网站，目标站点可能拒绝了自动分析请求")
            }

            val parsed = try {
                socket.use { sock ->
                    writeRequest(sock.getOutputStream(), currentUrl, host, port, headers)
                    val input = BufferedInputStream(sock.getInputStream(), 32 * 1024)
                    HttpResponseParser.parse(input, MAX_BODY_BYTES)
                }
            } catch (e: Exception) {
                AppLogger.w(TAG, "ECH fetch failed for $host: ${e.message}")
                return Result.Failed("无法访问网站，目标站点可能拒绝了自动分析请求")
            } ?: return Result.Failed("无法访问网站，目标站点可能拒绝了自动分析请求")

            if (parsed.statusCode in listOf(301, 302, 303, 307, 308)) {
                val location = HttpResponseParser.headerValue(parsed.headers, "location")
                val next = location?.let { currentUrl.resolve(it) }
                if (next != null && next.isHttps) {
                    currentUrl = next
                    return@repeat
                }
                // Redirect target is not a usable HTTPS URL: report this response.
                return Result.Success(parsed.statusCode, parsed.headers, parsed.body)
            }
            return Result.Success(parsed.statusCode, parsed.headers, parsed.body)
        }
        return Result.Failed("站点重定向次数过多")
    }

    private fun openTlsConnection(
        host: String,
        port: Int,
        addresses: List<InetAddress>,
        echConfigList: ByteArray
    ): SSLSocket {
        val sslContext = SSLContext.getInstance("TLS", "Conscrypt")
        val trustManager = ConscryptEchForwarder.EchPolicyTrustManager(
            delegate = TlsUpstreamConnector.buildUpstreamTrustManager(emptyList()),
            targetHost = host,
            echRequired = true
        )
        sslContext.init(null, arrayOf(trustManager), null)
        val factory = sslContext.socketFactory

        var lastError: Exception? = null
        for (address in addresses.take(MAX_CONNECT_ATTEMPTS)) {
            val raw = Socket()
            try {
                raw.tcpNoDelay = true
                raw.connect(InetSocketAddress(address, port), CONNECT_TIMEOUT_MS)
                raw.soTimeout = READ_TIMEOUT_MS
                val sslSocket = factory.createSocket(raw, host, port, true) as SSLSocket
                Conscrypt.setHostname(sslSocket, host)
                try {
                    val params = sslSocket.sslParameters
                    params.applicationProtocols = arrayOf("http/1.1")
                    sslSocket.sslParameters = params
                } catch (_: Exception) {
                }
                Conscrypt.setEchConfigList(sslSocket, echConfigList)
                sslSocket.startHandshake()

                val peerCert = sslSocket.session.peerCertificates
                    .firstOrNull { it is X509Certificate } as? X509Certificate
                if (peerCert == null || !CertificateHostnameMatcher.matches(host, peerCert)) {
                    try { sslSocket.close() } catch (_: Exception) {}
                    throw IOException("ECH fetch: certificate does not match host '$host'")
                }
                AppLogger.d(TAG, "ECH fetch connected: $host via $address")
                return sslSocket
            } catch (e: EchRejectedException) {
                try { raw.close() } catch (_: Exception) {}
                throw e
            } catch (e: Exception) {
                lastError = e
                try { raw.close() } catch (_: Exception) {}
                AppLogger.d(TAG, "ECH fetch attempt failed for $host via $address: ${e.message}")
            }
        }
        throw lastError ?: IOException("ECH fetch: could not connect to $host")
    }

    private fun writeRequest(
        out: java.io.OutputStream,
        httpUrl: okhttp3.HttpUrl,
        host: String,
        port: Int,
        headers: List<Pair<String, String>>
    ) {
        val sb = StringBuilder()
        val path = httpUrl.encodedPath.ifEmpty { "/" }
        val query = httpUrl.encodedQuery
        val target = if (query.isNullOrEmpty()) path else "$path?$query"
        sb.append("GET ").append(target).append(" HTTP/1.1\r\n")
        val hostPart = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        sb.append("Host: ").append(hostPart)
        if (port != 443) sb.append(':').append(port)
        sb.append("\r\n")
        for ((name, value) in headers) {
            val lower = name.lowercase(Locale.ROOT)
            if (lower == "host" || lower == "connection" || lower == "accept-encoding") continue
            sb.append(name).append(": ").append(value).append("\r\n")
        }
        sb.append("Accept-Encoding: gzip\r\n")
        sb.append("Connection: close\r\n")
        sb.append("\r\n")
        out.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
        out.flush()
    }

    private fun ensureProvider(): Boolean {
        return try {
            if (Security.getProvider("Conscrypt") == null) {
                Security.insertProviderAt(Conscrypt.newProvider(), 1)
            }
            true
        } catch (e: Exception) {
            AppLogger.e(TAG, "Failed to register Conscrypt provider", e)
            false
        }
    }
}
