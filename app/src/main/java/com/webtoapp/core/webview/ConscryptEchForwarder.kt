package com.webtoapp.core.webview

import android.content.Context
import com.webtoapp.core.dns.EchConfigResolver
import com.webtoapp.core.logging.AppLogger
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.conscrypt.Conscrypt
import org.conscrypt.DomainEncryptionMode
import org.conscrypt.EchRejectedException
import org.conscrypt.NetworkSecurityPolicy
import org.conscrypt.metrics.CertificateTransparencyVerificationReason
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.zip.GZIPInputStream
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * Conscrypt-based ECH upstream for the MITM bridge (system-WebView engine).
 *
 * Why this exists next to [CronetForwarder]: Cronet's public DnsOptions API
 * has no DoH server setting and no ECH switch (verified against the pinned
 * cronet-api 143.7445.0 classes), so the Cronet leg can only discover
 * ECHConfigLists through the system resolver's plain-DNS HTTPS queries —
 * which on filtered networks return nothing, and the ClientHello goes out
 * with a plaintext SNI. Conscrypt 2.7.0 exposes the missing piece directly:
 * [Conscrypt.setEchConfigList] takes the ECHConfigList bytes, and
 * [EchConfigResolver] fetches them over the app's configured DoH endpoint.
 *
 * The forwarder speaks HTTP/1.1 upstream (the bridge already restricts the
 * WebView side of an upstream-engine connection to HTTP/1.1) and mirrors
 * [CronetForwarder.forward]'s contract exactly: it serialises the response
 * onto the bridge sink as HTTP/1.1 with chunked framing, returns false when
 * the request failed before the response head was written, and throws
 * [IOException] when it failed mid-body.
 *
 * Policy: when the host publishes an ECHConfig, the TLS policy for that host
 * is REQUIRED — a server-side ECH rejection fails the request instead of
 * silently retrying with a plaintext SNI (the failure mode that made the old
 * Cronet path look "enabled" while doing nothing). Hosts without a published
 * config get a plain Conscrypt TLS connection to the DoH-resolved address.
 */
object ConscryptEchForwarder {

    private const val TAG = "ConscryptEchForwarder"
    private const val IO_BUFFER = 32 * 1024
    private const val MAX_HEADER_BYTES = 64 * 1024
    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val READ_TIMEOUT_MS = 60_000
    private const val MAX_CONNECT_ATTEMPTS = 3

    private val HOP_BY_HOP_RESPONSE_HEADERS = setOf(
        "content-length", "transfer-encoding", "connection", "keep-alive",
        "proxy-authenticate", "proxy-authorization", "upgrade"
    )

    /** Methods that carry a body even when the bridge read none (send CL: 0). */
    private val BODY_EXPECTED_METHODS = setOf("POST", "PUT", "PATCH")

    @Volatile private var dohUrl: String = ""
    @Volatile private var customCaAnchors: List<X509Certificate> = emptyList()
    private val providerReady = AtomicBoolean(false)

    fun start(
        context: Context,
        dohUrl: String,
        customCaAnchors: List<X509Certificate> = emptyList()
    ) {
        this.dohUrl = dohUrl
        this.customCaAnchors = customCaAnchors
        ensureProvider()
        AppLogger.i(
            TAG,
            "ECH upstream (Conscrypt) started: doh=${dohUrl.take(48)} providerReady=${providerReady.get()}"
        )
    }

    /**
     * Ready only when a DoH endpoint is configured AND the bundled Conscrypt
     * provider registered — in generated APKs whose template excludes
     * libconscrypt_jni.so the provider never registers and the bridge stays on
     * its classic relay instead of failing every request.
     */
    fun isReady(): Boolean = dohUrl.isNotBlank() && providerReady.get()

    fun stop() {
        dohUrl = ""
        customCaAnchors = emptyList()
        EchConfigResolver.clearCache()
    }

    private fun ensureProvider() {
        if (providerReady.get()) return
        synchronized(this) {
            if (providerReady.get()) return
            try {
                if (Security.getProvider("Conscrypt") == null) {
                    Security.insertProviderAt(Conscrypt.newProvider(), 1)
                }
                providerReady.set(true)
            } catch (e: Exception) {
                AppLogger.e(TAG, "Failed to register Conscrypt provider", e)
            }
        }
    }

    /**
     * Forwards one request and streams the response onto [sink] as HTTP/1.1.
     * Same contract as [CronetForwarder.forward].
     */
    fun forward(
        context: Context,
        method: String,
        url: String,
        headers: List<Pair<String, String>>,
        body: ByteArray?,
        sink: OutputStream,
        clientWantsClose: Boolean,
        hostForHint: String,
        portForHint: Int
    ): Boolean {
        val httpUrl = url.toHttpUrlOrNull() ?: return false
        if (!httpUrl.isHttps) return false
        val host = httpUrl.host
        val port = httpUrl.port

        val records = EchConfigResolver.resolve(dohUrl, host)
        val addresses = records.addresses.ifEmpty {
            // DoH unreachable: keep browsing alive on the system resolver, the
            // same fallback DnsManager applies in non-strict mode. The TLS
            // handshake below still uses any ECHConfig we did obtain.
            try {
                InetAddress.getAllByName(host).toList()
            } catch (e: Exception) {
                AppLogger.w(TAG, "ECH forward: system DNS fallback failed for $host: ${e.message}")
                emptyList()
            }
        }
        if (addresses.isEmpty()) {
            AppLogger.w(TAG, "ECH forward: no address for $host")
            return false
        }

        val socket = try {
            openTlsConnection(host, port, addresses, records.echConfigList)
        } catch (e: EchRejectedException) {
            AppLogger.w(
                TAG,
                "ECH rejected by $host (policy REQUIRED; not retrying with plaintext SNI): ${e.message}"
            )
            return false
        } catch (e: Exception) {
            AppLogger.w(TAG, "ECH forward connect failed for $host: ${e.message}")
            return false
        }

        socket.use { sock ->
            try {
                writeRequest(sock.getOutputStream(), method, requestTarget(httpUrl), host, port, headers, body)
            } catch (e: IOException) {
                AppLogger.w(TAG, "ECH forward write failed for $host: ${e.message}")
                return false
            }
            val input = BufferedInputStream(sock.getInputStream(), IO_BUFFER)
            return relayResponse(input, method, sink, clientWantsClose, host)
        }
    }

    private fun requestTarget(httpUrl: HttpUrl): String {
        val path = httpUrl.encodedPath.ifEmpty { "/" }
        val query = httpUrl.encodedQuery
        return if (query.isNullOrEmpty()) path else "$path?$query"
    }

    private fun openTlsConnection(
        host: String,
        port: Int,
        addresses: List<InetAddress>,
        echConfigList: ByteArray?
    ): SSLSocket {
        ensureProvider()
        val sslContext = SSLContext.getInstance("TLS", "Conscrypt")
        val trustManager = EchPolicyTrustManager(
            delegate = TlsUpstreamConnector.buildUpstreamTrustManager(customCaAnchors),
            targetHost = host,
            echRequired = echConfigList != null
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
                if (echConfigList != null) {
                    Conscrypt.setEchConfigList(sslSocket, echConfigList)
                }
                sslSocket.startHandshake()

                // SSLSocket validates the chain but not the hostname — verify the
                // peer certificate covers the host, mirroring TlsUpstreamConnector.
                val peerCert = sslSocket.session.peerCertificates
                    .firstOrNull { it is X509Certificate } as? X509Certificate
                if (peerCert == null || !CertificateHostnameMatcher.matches(host, peerCert)) {
                    try { sslSocket.close() } catch (_: Exception) {}
                    throw IOException("ECH upstream: certificate does not match host '$host'")
                }
                AppLogger.d(
                    TAG,
                    "ECH upstream connected: $host via $address ech=${echConfigList != null} " +
                        "alpn=${try { sslSocket.applicationProtocol } catch (_: Exception) { null }}"
                )
                return sslSocket
            } catch (e: EchRejectedException) {
                try { raw.close() } catch (_: Exception) {}
                // The config itself was rejected; another address would present
                // the same config to (usually) the same service. Surface it.
                throw e
            } catch (e: Exception) {
                lastError = e
                try { raw.close() } catch (_: Exception) {}
                AppLogger.d(TAG, "ECH upstream attempt failed for $host via $address: ${e.message}")
            }
        }
        throw lastError ?: IOException("ECH upstream: could not connect to $host")
    }

    private fun writeRequest(
        out: OutputStream,
        method: String,
        target: String,
        host: String,
        port: Int,
        headers: List<Pair<String, String>>,
        body: ByteArray?
    ) {
        val sb = StringBuilder()
        sb.append(method).append(' ').append(target).append(" HTTP/1.1\r\n")
        val hostPart = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        sb.append("Host: ").append(hostPart)
        if (port != 443) sb.append(':').append(port)
        sb.append("\r\n")
        for ((name, value) in headers) {
            // We always ask for gzip and decode it ourselves (Cronet parity:
            // the relayed response never carries the upstream encoding).
            if (name.equals("accept-encoding", ignoreCase = true)) continue
            sb.append(name).append(": ").append(value).append("\r\n")
        }
        sb.append("Accept-Encoding: gzip\r\n")
        if (body != null) {
            sb.append("Content-Length: ").append(body.size).append("\r\n")
        } else if (method.uppercase(Locale.ROOT) in BODY_EXPECTED_METHODS) {
            sb.append("Content-Length: 0\r\n")
        }
        sb.append("Connection: close\r\n")
        sb.append("\r\n")
        out.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
        if (body != null && body.isNotEmpty()) {
            out.write(body)
        }
        out.flush()
    }

    /**
     * Reads one upstream response and re-frames it onto [sink]. Returns false
     * when the response could not be read at all (nothing written yet); throws
     * [IOException] for failures after the head went out.
     */
    private fun relayResponse(
        input: InputStream,
        method: String,
        sink: OutputStream,
        clientWantsClose: Boolean,
        host: String
    ): Boolean {
        var statusCode = -1
        var statusText = "Unknown"
        var responseHeaders: List<Pair<String, String>> = emptyList()
        try {
            while (true) {
                val line = readHttpLine(input) ?: return false
                val parts = line.split(' ', limit = 3)
                val code = parts.getOrNull(1)?.toIntOrNull() ?: return false
                val headers = readHeaders(input) ?: return false
                // Informational responses (100 Continue, 103, ...) precede the
                // real one; 101 is terminal (upgrades never reach this engine).
                if (code in 100..199 && code != 101) continue
                statusCode = code
                statusText = parts.getOrNull(2)?.takeIf { it.isNotEmpty() } ?: "Unknown"
                responseHeaders = headers
                break
            }
        } catch (e: IOException) {
            return false
        }

        val bodyPermitted = !method.equals("HEAD", ignoreCase = true) &&
            statusCode >= 200 && statusCode != 204 && statusCode != 205 && statusCode != 304

        var bodyStream: InputStream = input
        var decodeGzip = false
        if (bodyPermitted) {
            val transferEncoding = headerValue(responseHeaders, "transfer-encoding")
                ?.lowercase(Locale.ROOT).orEmpty()
            val contentLength = headerValue(responseHeaders, "content-length")
                ?.trim()?.toLongOrNull()
            bodyStream = when {
                transferEncoding.contains("chunked") -> ChunkedInputStream(input)
                contentLength != null -> LengthInputStream(input, contentLength)
                else -> input // Connection: close was requested; body runs to EOF.
            }
            val contentEncoding = headerValue(responseHeaders, "content-encoding")
                ?.trim()?.lowercase(Locale.ROOT)
            if (contentEncoding == "gzip") {
                bodyStream = try {
                    GZIPInputStream(bodyStream)
                } catch (e: IOException) {
                    return false // corrupt gzip header — still pre-head, fail cleanly
                }
                decodeGzip = true
            }
        }

        writeHead(sink, statusCode, statusText, responseHeaders, clientWantsClose, bodyPermitted, decodeGzip)
        if (!bodyPermitted) {
            sink.flush()
            AppLogger.d(TAG, "ech forward done: $statusCode (no body) url-host=$host")
            return true
        }

        val buffer = ByteArray(IO_BUFFER)
        while (true) {
            val read = bodyStream.read(buffer)
            if (read < 0) break
            if (read == 0) continue
            sink.write(read.toString(16).toByteArray(Charsets.US_ASCII))
            sink.write("\r\n".toByteArray(Charsets.US_ASCII))
            sink.write(buffer, 0, read)
            sink.write("\r\n".toByteArray(Charsets.US_ASCII))
        }
        sink.write("0\r\n\r\n".toByteArray(Charsets.US_ASCII))
        sink.flush()
        AppLogger.d(TAG, "ech forward done: $statusCode url-host=$host")
        return true
    }

    private fun writeHead(
        sink: OutputStream,
        statusCode: Int,
        statusText: String,
        headers: List<Pair<String, String>>,
        clientWantsClose: Boolean,
        chunked: Boolean,
        stripContentEncoding: Boolean
    ) {
        val sb = StringBuilder()
        sb.append("HTTP/1.1 ").append(statusCode).append(' ').append(statusText).append("\r\n")
        for ((name, value) in headers) {
            val lower = name.lowercase(Locale.ROOT)
            if (lower in HOP_BY_HOP_RESPONSE_HEADERS) continue
            // Only strip Content-Encoding when we actually decoded the body;
            // an undecoded body relayed without its encoding header is corrupt.
            if (stripContentEncoding && lower == "content-encoding") continue
            sb.append(name).append(": ").append(value).append("\r\n")
        }
        if (chunked) {
            sb.append("Transfer-Encoding: chunked\r\n")
        }
        sb.append("Connection: ").append(if (clientWantsClose) "close" else "keep-alive").append("\r\n")
        sb.append("\r\n")
        sink.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
    }

    private fun readHeaders(input: InputStream): List<Pair<String, String>>? {
        val headers = mutableListOf<Pair<String, String>>()
        while (true) {
            val line = readHttpLine(input) ?: return null
            if (line.isEmpty()) return headers
            if ((line[0] == ' ' || line[0] == '\t') && headers.isNotEmpty()) {
                // obs-fold continuation of the previous header value.
                val last = headers.removeAt(headers.lastIndex)
                headers += last.first to (last.second + " " + line.trim())
                continue
            }
            val idx = line.indexOf(':')
            if (idx > 0) {
                headers += line.substring(0, idx).trim() to line.substring(idx + 1).trim()
            }
        }
    }

    private fun headerValue(headers: List<Pair<String, String>>, name: String): String? =
        headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    private fun readHttpLine(input: InputStream): String? {
        val bytes = ByteArrayOutputStream()
        while (true) {
            val next = input.read()
            if (next < 0) {
                return if (bytes.size() == 0) null
                else bytes.toString(Charsets.ISO_8859_1.name())
            }
            if (next == 0x0A) {
                val raw = bytes.toByteArray()
                val length = if (raw.isNotEmpty() && raw.last() == '\r'.code.toByte()) raw.size - 1 else raw.size
                return String(raw, 0, length, Charsets.ISO_8859_1)
            }
            bytes.write(next)
            if (bytes.size() > MAX_HEADER_BYTES) throw IOException("HTTP line too long")
        }
    }

    /** Serves the decoded body of a `Transfer-Encoding: chunked` response. */
    private class ChunkedInputStream(private val input: InputStream) : InputStream() {
        private var remainingInChunk = 0
        private var finished = false

        override fun read(): Int {
            val single = ByteArray(1)
            val n = read(single, 0, 1)
            return if (n == -1) -1 else single[0].toInt() and 0xFF
        }

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            if (finished) return -1
            if (remainingInChunk == 0 && !advanceChunk()) return -1
            val n = input.read(buffer, offset, minOf(length, remainingInChunk))
            if (n == -1) throw IOException("Unexpected EOF in chunked body")
            remainingInChunk -= n
            if (remainingInChunk == 0) {
                readLine(input) // trailing CRLF after the chunk data
            }
            return n
        }

        private fun advanceChunk(): Boolean {
            val sizeLine = readLine(input) ?: run {
                finished = true
                return false
            }
            val size = sizeLine.substringBefore(';').trim().toIntOrNull(16)
                ?: throw IOException("Bad chunk size: $sizeLine")
            if (size == 0) {
                // Consume trailers up to the empty line.
                while (true) {
                    val trailer = readLine(input) ?: break
                    if (trailer.isEmpty()) break
                }
                finished = true
                return false
            }
            remainingInChunk = size
            return true
        }

        private fun readLine(stream: InputStream): String? {
            val bytes = ByteArrayOutputStream()
            while (true) {
                val next = stream.read()
                if (next < 0) {
                    return if (bytes.size() == 0) null else bytes.toString(Charsets.ISO_8859_1.name())
                }
                if (next == 0x0A) {
                    val raw = bytes.toByteArray()
                    val length = if (raw.isNotEmpty() && raw.last() == '\r'.code.toByte()) raw.size - 1 else raw.size
                    return String(raw, 0, length, Charsets.ISO_8859_1)
                }
                bytes.write(next)
                if (bytes.size() > MAX_HEADER_BYTES) throw IOException("Chunk line too long")
            }
        }
    }

    /** Serves at most [length] bytes of a fixed-length response body. */
    private class LengthInputStream(
        private val input: InputStream,
        private var remaining: Long
    ) : InputStream() {
        override fun read(): Int {
            if (remaining <= 0) return -1
            val value = input.read()
            if (value == -1) throw IOException("Unexpected EOF in fixed-length body")
            remaining--
            return value
        }

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            if (remaining <= 0) return -1
            val n = input.read(buffer, offset, minOf(length.toLong(), remaining).toInt())
            if (n == -1) throw IOException("Unexpected EOF in fixed-length body")
            remaining -= n
            return n
        }
    }

    /**
     * Trust manager that exposes the ECH policy Conscrypt looks up reflectively:
     * [org.conscrypt.SSLParametersImpl] calls `getNetworkSecurityPolicy()` on the
     * X509TrustManager handed to SSLContext.init and asks it, per host, whether
     * ECH is REQUIRED / ENABLED / DISABLED. Without this method being present
     * (and kept by R8) [Conscrypt.setEchConfigList] is silently ignored.
     */
    class EchPolicyTrustManager(
        private val delegate: X509TrustManager,
        private val targetHost: String,
        private val echRequired: Boolean
    ) : X509TrustManager {

        private val policy = object : NetworkSecurityPolicy {
            override fun isCertificateTransparencyVerificationRequired(hostname: String): Boolean = false

            override fun getCertificateTransparencyVerificationReason(
                hostname: String
            ): CertificateTransparencyVerificationReason = CertificateTransparencyVerificationReason.UNKNOWN

            override fun getDomainEncryptionMode(hostname: String): DomainEncryptionMode =
                if (echRequired && hostname.equals(targetHost, ignoreCase = true)) {
                    DomainEncryptionMode.REQUIRED
                } else {
                    DomainEncryptionMode.DISABLED
                }
        }

        fun getNetworkSecurityPolicy(): NetworkSecurityPolicy = policy

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            delegate.checkClientTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            delegate.checkServerTrusted(chain, authType)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
    }
}
