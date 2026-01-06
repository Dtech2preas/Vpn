package com.dtech.vpn.net

import java.nio.ByteBuffer

object Packet {
    const val IP4_HEADER_SIZE = 20
    const val TCP_HEADER_SIZE = 20
    const val UDP_HEADER_SIZE = 8

    const val PROTOCOL_TCP = 6
    const val PROTOCOL_UDP = 17

    const val TCP_FLAG_FIN = 0x01
    const val TCP_FLAG_SYN = 0x02
    const val TCP_FLAG_RST = 0x04
    const val TCP_FLAG_PSH = 0x08
    const val TCP_FLAG_ACK = 0x10

    fun getIPVersion(buffer: ByteBuffer): Int {
        return (buffer.get(0).toInt() shr 4) and 0x0F
    }

    fun getIPHeaderLength(buffer: ByteBuffer): Int {
        return (buffer.get(0).toInt() and 0x0F) * 4
    }

    fun getIPTotalLength(buffer: ByteBuffer): Int {
        return buffer.getShort(2).toInt() and 0xFFFF
    }

    fun getIPProtocol(buffer: ByteBuffer): Int {
        return buffer.get(9).toInt() and 0xFF
    }

    fun getIPSrcAddress(buffer: ByteBuffer): String {
        return ipToString(buffer.getInt(12))
    }

    fun getIPDstAddress(buffer: ByteBuffer): String {
        return ipToString(buffer.getInt(16))
    }

    fun getIPSrcInt(buffer: ByteBuffer): Int = buffer.getInt(12)
    fun getIPDstInt(buffer: ByteBuffer): Int = buffer.getInt(16)

    // TCP Getters
    fun getTcpSrcPort(buffer: ByteBuffer, ipHeaderLen: Int): Int {
        return buffer.getShort(ipHeaderLen).toInt() and 0xFFFF
    }

    fun getTcpDstPort(buffer: ByteBuffer, ipHeaderLen: Int): Int {
        return buffer.getShort(ipHeaderLen + 2).toInt() and 0xFFFF
    }

    fun getTcpSeqNum(buffer: ByteBuffer, ipHeaderLen: Int): Long {
        return buffer.getInt(ipHeaderLen + 4).toLong() and 0xFFFFFFFFL
    }

    fun getTcpAckNum(buffer: ByteBuffer, ipHeaderLen: Int): Long {
        return buffer.getInt(ipHeaderLen + 8).toLong() and 0xFFFFFFFFL
    }

    fun getTcpHeaderLength(buffer: ByteBuffer, ipHeaderLen: Int): Int {
        return ((buffer.get(ipHeaderLen + 12).toInt() shr 4) and 0x0F) * 4
    }

    fun getTcpFlags(buffer: ByteBuffer, ipHeaderLen: Int): Int {
        return buffer.get(ipHeaderLen + 13).toInt() and 0xFF
    }

    // UDP Getters
    fun getUdpSrcPort(buffer: ByteBuffer, ipHeaderLen: Int): Int {
        return buffer.getShort(ipHeaderLen).toInt() and 0xFFFF
    }

    fun getUdpDstPort(buffer: ByteBuffer, ipHeaderLen: Int): Int {
        return buffer.getShort(ipHeaderLen + 2).toInt() and 0xFFFF
    }

    fun getUdpLength(buffer: ByteBuffer, ipHeaderLen: Int): Int {
        return buffer.getShort(ipHeaderLen + 4).toInt() and 0xFFFF
    }

    // Helpers
    private fun ipToString(ip: Int): String {
        return String.format("%d.%d.%d.%d",
            (ip shr 24) and 0xFF,
            (ip shr 16) and 0xFF,
            (ip shr 8) and 0xFF,
            ip and 0xFF)
    }

    // Checksums
    fun calculateIPChecksum(buffer: ByteBuffer, offset: Int, length: Int): Int {
        var sum = 0
        var i = 0
        while (i < length) {
            // Skip checksum field at offset + 10
            if (i == 10) {
                i += 2
                continue
            }
            val word = buffer.getShort(offset + i).toInt() and 0xFFFF
            sum += word
            i += 2
        }
        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    fun updateIPChecksum(buffer: ByteBuffer, offset: Int, length: Int) {
        val checksum = calculateIPChecksum(buffer, offset, length)
        buffer.putShort(offset + 10, checksum.toShort())
    }

    fun calculateTCPChecksum(buffer: ByteBuffer, ipHeaderLen: Int, ipTotalLen: Int, srcIp: Int, dstIp: Int) {
        val tcpLen = ipTotalLen - ipHeaderLen
        var sum = 0

        // Pseudo Header
        sum += (srcIp shr 16) and 0xFFFF
        sum += srcIp and 0xFFFF
        sum += (dstIp shr 16) and 0xFFFF
        sum += dstIp and 0xFFFF
        sum += PROTOCOL_TCP
        sum += tcpLen

        // TCP Header + Data
        val tcpOffset = ipHeaderLen
        for (i in 0 until tcpLen step 2) {
            if (i == 16) continue // Skip checksum field
            var word = 0
            if (i + 1 < tcpLen) {
                word = buffer.getShort(tcpOffset + i).toInt() and 0xFFFF
            } else {
                // Odd byte at the end
                word = (buffer.get(tcpOffset + i).toInt() and 0xFF) shl 8
            }
            sum += word
        }

        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val checksum = sum.inv() and 0xFFFF
        buffer.putShort(tcpOffset + 16, checksum.toShort())
    }

    fun calculateUDPChecksum(buffer: ByteBuffer, ipHeaderLen: Int, ipTotalLen: Int, srcIp: Int, dstIp: Int) {
        val udpLen = ipTotalLen - ipHeaderLen
        var sum = 0

        // Pseudo Header
        sum += (srcIp shr 16) and 0xFFFF
        sum += srcIp and 0xFFFF
        sum += (dstIp shr 16) and 0xFFFF
        sum += dstIp and 0xFFFF
        sum += PROTOCOL_UDP
        sum += udpLen

        // UDP Header + Data
        val udpOffset = ipHeaderLen
        for (i in 0 until udpLen step 2) {
             if (i == 6) continue // Skip checksum
             var word = 0
             if (i + 1 < udpLen) {
                 word = buffer.getShort(udpOffset + i).toInt() and 0xFFFF
             } else {
                 word = (buffer.get(udpOffset + i).toInt() and 0xFF) shl 8
             }
             sum += word
        }

        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        var checksum = sum.inv() and 0xFFFF
        if (checksum == 0) checksum = 0xFFFF // UDP checksum 0 means no checksum, so strict 0 is encoded as FFFF
        buffer.putShort(udpOffset + 6, checksum.toShort())
    }
}
