package com.webtoapp.core.dns

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * Wire-format tests for [EchConfigResolver]'s DNS message parser — the piece
 * that extracts the ECHConfigList out of HTTPS records for the Conscrypt ECH
 * upstream. Messages are hand-crafted so the expectations are independent of
 * the parser under test.
 */
class EchConfigResolverTest {

    private fun w16(out: ByteArrayOutputStream, value: Int) {
        out.write((value shr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun w32(out: ByteArrayOutputStream, value: Long) {
        w16(out, (value shr 16).toInt())
        w16(out, (value and 0xFFFF).toInt())
    }

    private fun name(out: ByteArrayOutputStream, host: String) {
        for (label in host.split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
    }

    /** Header + one question; answers are appended by the caller via [answer]. */
    private fun message(id: Int, qname: String, qtype: Int, answerCount: Int): ByteArrayOutputStream {
        val out = ByteArrayOutputStream()
        w16(out, id)
        w16(out, 0x8180) // response, RD+RA, no error
        w16(out, 1)
        w16(out, answerCount)
        w16(out, 0)
        w16(out, 0)
        name(out, qname)
        w16(out, qtype)
        w16(out, 1)
        return out
    }

    /** One answer RR whose name is a compression pointer to the question name. */
    private fun answer(out: ByteArrayOutputStream, type: Int, ttl: Long, rdata: ByteArray) {
        out.write(0xC0)
        out.write(0x0C)
        w16(out, type)
        w16(out, 1)
        w32(out, ttl)
        w16(out, rdata.size)
        out.write(rdata)
    }

    private fun httpsRdata(priority: Int, target: String, params: List<Pair<Int, ByteArray>>): ByteArray {
        val out = ByteArrayOutputStream()
        w16(out, priority)
        name(out, target)
        for ((key, value) in params) {
            w16(out, key)
            w16(out, value.size)
            out.write(value)
        }
        return out.toByteArray()
    }

    @Test
    fun `https service mode record yields the ech param bytes`() {
        val echBytes = byteArrayOf(0x00, 0x03, 0xDE.toByte(), 0xAD.toByte())
        val out = message(0x4242, "example.com", 65, 1)
        answer(
            out, 65, 300,
            httpsRdata(
                priority = 1,
                target = "svc.example.com",
                params = listOf(
                    1 to "h2".toByteArray(Charsets.US_ASCII), // alpn — skipped
                    5 to echBytes // ech
                )
            )
        )

        val parsed = EchConfigResolver.parseMessage(out.toByteArray(), 0x4242)

        assertThat(parsed.echConfigList!!.toList()).containsExactlyElementsIn(echBytes.toList())
        assertThat(parsed.aliasTarget).isNull()
        assertThat(parsed.minTtlSeconds).isEqualTo(300)
    }

    @Test
    fun `https alias mode record yields the alias target and no ech`() {
        val out = message(0x4243, "example.com", 65, 1)
        answer(out, 65, 120, httpsRdata(priority = 0, target = "alias.example.net", params = emptyList()))

        val parsed = EchConfigResolver.parseMessage(out.toByteArray(), 0x4243)

        assertThat(parsed.echConfigList).isNull()
        assertThat(parsed.aliasTarget).isEqualTo("alias.example.net")
    }

    @Test
    fun `lowest priority service record with an ech param wins`() {
        val echPrio2 = byteArrayOf(0x02)
        val echPrio1 = byteArrayOf(0x01)
        val out = message(0x4244, "example.com", 65, 2)
        answer(out, 65, 300, httpsRdata(2, "b.example.com", listOf(5 to echPrio2)))
        answer(out, 65, 300, httpsRdata(1, "a.example.com", listOf(5 to echPrio1)))

        val parsed = EchConfigResolver.parseMessage(out.toByteArray(), 0x4244)

        assertThat(parsed.echConfigList!!.toList()).containsExactlyElementsIn(echPrio1.toList())
    }

    @Test
    fun `a record yields the address`() {
        val out = message(0x4245, "example.com", 1, 1)
        answer(out, 1, 60, byteArrayOf(203.toByte(), 0, 113, 7))

        val parsed = EchConfigResolver.parseMessage(out.toByteArray(), 0x4245)

        assertThat(parsed.addresses).hasSize(1)
        assertThat(parsed.addresses[0].hostAddress).isEqualTo("203.0.113.7")
    }

    @Test
    fun `cname and address in one message are both surfaced`() {
        val out = message(0x4246, "example.com", 1, 2)
        val cnameRdata = ByteArrayOutputStream().also { name(it, "cdn.example.net") }.toByteArray()
        answer(out, 5, 60, cnameRdata)
        answer(out, 1, 60, byteArrayOf(198.toByte(), 51, 100, 9))

        val parsed = EchConfigResolver.parseMessage(out.toByteArray(), 0x4246)

        assertThat(parsed.cnameTarget).isEqualTo("cdn.example.net")
        assertThat(parsed.addresses.map { it.hostAddress }).containsExactly("198.51.100.9")
    }

    @Test
    fun `response with a mismatched id is rejected`() {
        val out = message(0x4247, "example.com", 65, 0)

        val result = runCatching { EchConfigResolver.parseMessage(out.toByteArray(), 0x9999) }

        assertThat(result.isFailure).isTrue()
    }

    @Test
    fun `query builder emits a well formed question`() {
        val query = EchConfigResolver.buildQuery("example.com", 65, 0x1111)

        assertThat(query[0].toInt() and 0xFF).isEqualTo(0x11)
        assertThat(query[1].toInt() and 0xFF).isEqualTo(0x11)
        // Trailing QTYPE=65, QCLASS=1.
        val tail = query.takeLast(4).map { it.toInt() and 0xFF }
        assertThat(tail).containsExactly(0, 65, 0, 1).inOrder()
    }
}
