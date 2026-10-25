package com.webtoapp.core.pwa

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream

/**
 * Pure-JVM tests for [HttpResponseParser]. This file must never import
 * Conscrypt: the unit-test runtime classpath excludes conscrypt-android
 * (its Android-ABI .so cannot load under Robolectric), so any test that
 * touches Conscrypt fails before it runs.
 */
class HttpResponseParserTest {

    private fun parse(raw: String, maxBody: Int = 1024 * 1024): HttpResponseParser.Parsed? =
        HttpResponseParser.parse(ByteArrayInputStream(raw.toByteArray(Charsets.ISO_8859_1)), maxBody)

    @Test
    fun `content-length body is read exactly`() {
        val parsed = parse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/html\r\n\r\nhello")!!
        assertThat(parsed.statusCode).isEqualTo(200)
        assertThat(parsed.headers).contains(Pair("Content-Type", "text/html"))
        assertThat(parsed.body.toString(Charsets.UTF_8)).isEqualTo("hello")
    }

    @Test
    fun `chunked body is decoded across chunks`() {
        val parsed = parse(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
                "5\r\nhello\r\n" +
                "1;ext=1\r\n \r\n" +
                "0\r\nX-Trailer: yes\r\n\r\n"
        )!!
        assertThat(parsed.statusCode).isEqualTo(200)
        assertThat(parsed.body.toString(Charsets.UTF_8)).isEqualTo("hello ")
    }

    @Test
    fun `gzip body is decompressed`() {
        val gzipped = ByteArrayOutputStream().also { out ->
            GZIPOutputStream(out).use { it.write("hello gzip".toByteArray(Charsets.UTF_8)) }
        }.toByteArray()
        val head = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ${gzipped.size}\r\n\r\n"
            .toByteArray(Charsets.ISO_8859_1)
        val parsed = HttpResponseParser.parse(
            ByteArrayInputStream(head + gzipped), 1024 * 1024
        )!!
        assertThat(parsed.body.toString(Charsets.UTF_8)).isEqualTo("hello gzip")
    }

    @Test
    fun `informational response is skipped`() {
        val parsed = parse(
            "HTTP/1.1 100 Continue\r\n\r\n" +
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
        )!!
        assertThat(parsed.statusCode).isEqualTo(200)
        assertThat(parsed.body.toString(Charsets.UTF_8)).isEqualTo("hi")
    }

    @Test
    fun `204 has no body even with following bytes`() {
        val parsed = parse("HTTP/1.1 204 No Content\r\n\r\n")!!
        assertThat(parsed.statusCode).isEqualTo(204)
        assertThat(parsed.body).isEmpty()
    }

    @Test
    fun `body without length runs to EOF`() {
        val parsed = parse("HTTP/1.1 200 OK\r\n\r\nhello-eof")!!
        assertThat(parsed.body.toString(Charsets.UTF_8)).isEqualTo("hello-eof")
    }

    @Test
    fun `body is capped at maxBodyBytes`() {
        val parsed = parse("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789", maxBody = 4)!!
        assertThat(parsed.body.toString(Charsets.UTF_8)).isEqualTo("0123")
    }

    @Test
    fun `empty input returns null`() {
        assertThat(parse("")).isNull()
    }

    @Test
    fun `folded header continuation joins with a space`() {
        val parsed = parse(
            "HTTP/1.1 200 OK\r\nX-Long: first\r\n second\r\nContent-Length: 0\r\n\r\n"
        )!!
        assertThat(HttpResponseParser.headerValue(parsed.headers, "X-Long")).isEqualTo("first second")
    }
}
