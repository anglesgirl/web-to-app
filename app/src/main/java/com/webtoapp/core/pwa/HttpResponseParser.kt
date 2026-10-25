package com.webtoapp.core.pwa

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.zip.GZIPInputStream

/**
 * Minimal HTTP/1.1 response parser for [EchHttpFetcher].
 *
 * Deliberately free of any Conscrypt import so it stays unit-testable on the
 * JVM: the test runtime classpath excludes conscrypt-android (its Android-ABI
 * .so cannot load under Robolectric), and anything that touches Conscrypt
 * cannot run there. Only the socket setup lives in [EchHttpFetcher]; all
 * framing decisions live here.
 *
 * Returns null when no response head could be read at all. Throws
 * [IOException] for malformed framing after the head was read.
 */
object HttpResponseParser {

    private const val MAX_HEADER_BYTES = 64 * 1024

    data class Parsed(
        val statusCode: Int,
        val headers: List<Pair<String, String>>,
        val body: ByteArray
    )

    fun parse(input: InputStream, maxBodyBytes: Int): Parsed? {
        var statusCode = -1
        var headers: List<Pair<String, String>> = emptyList()
        while (true) {
            val line = readLine(input) ?: return null
            val parts = line.split(' ', limit = 3)
            val code = parts.getOrNull(1)?.toIntOrNull() ?: return null
            val readHeaders = readHeaders(input) ?: return null
            // Informational responses precede the real one; 101 is terminal
            // (an upgrade never reaches a plain GET fetch).
            if (code in 100..199 && code != 101) continue
            statusCode = code
            headers = readHeaders
            break
        }

        val bodyPermitted = statusCode >= 200 && statusCode != 204 && statusCode != 304
        if (!bodyPermitted) return Parsed(statusCode, headers, ByteArray(0))

        var bodyStream: InputStream = input
        val transferEncoding = headerValue(headers, "transfer-encoding")?.lowercase().orEmpty()
        val contentLength = headerValue(headers, "content-length")?.trim()?.toLongOrNull()
        bodyStream = when {
            transferEncoding.contains("chunked") -> ChunkedInputStream(input)
            contentLength != null -> LengthInputStream(input, contentLength)
            else -> input // Connection: close was requested; body runs to EOF.
        }
        if (headerValue(headers, "content-encoding")?.trim()?.lowercase() == "gzip") {
            bodyStream = GZIPInputStream(bodyStream)
        }

        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8 * 1024)
        var remaining = maxBodyBytes
        while (remaining > 0) {
            val read = bodyStream.read(buffer, 0, minOf(buffer.size, remaining))
            if (read < 0) break
            if (read == 0) continue
            out.write(buffer, 0, read)
            remaining -= read
        }
        return Parsed(statusCode, headers, out.toByteArray())
    }

    fun headerValue(headers: List<Pair<String, String>>, name: String): String? =
        headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    private fun readHeaders(input: InputStream): List<Pair<String, String>>? {
        val headers = mutableListOf<Pair<String, String>>()
        while (true) {
            val line = readLine(input) ?: return null
            if (line.isEmpty()) return headers
            if ((line[0] == ' ' || line[0] == '\t') && headers.isNotEmpty()) {
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

    private fun readLine(input: InputStream): String? {
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
}
