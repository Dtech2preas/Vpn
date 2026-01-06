package com.dtech.vpn.net

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer

class DnsForwarder(
    private val tun2Socks: Tun2Socks,
    private val session: Session,
    private val logger: (String) -> Unit
) {

    // Cache or reusable channel? DNS is short lived.
    // For simplicity, we open a new channel for each query.
    // Optimization: Keep a persistent connection to 8.8.8.8:53 if possible, but queries are async.
    // Each query is a new UDP packet.
    // We wrap it in TCP: [Len][Query]

    fun processPacket(buffer: ByteBuffer, ipHeaderLen: Int, udpHeaderLen: Int, payloadLen: Int) {
        val srcIp = Packet.getIPSrcInt(buffer)
        val dstIp = Packet.getIPDstInt(buffer) // Likely 8.8.8.8
        val srcPort = Packet.getUdpSrcPort(buffer, ipHeaderLen)
        val dstPort = Packet.getUdpDstPort(buffer, ipHeaderLen)

        // Extract DNS Query
        val query = ByteArray(payloadLen)
        buffer.position(ipHeaderLen + udpHeaderLen)
        buffer.get(query)

        // Launch thread to handle
        Thread {
            handleDnsQuery(srcIp, srcPort, dstIp, dstPort, query)
        }.start()
    }

    private fun handleDnsQuery(srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int, query: ByteArray) {
        var channel: ChannelDirectTCPIP? = null
        try {
            // Connect to Google DNS over TCP
            channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost("8.8.8.8")
            channel.setPort(53)
            channel.connect(5000)

            val out = channel.outputStream
            val `in` = channel.inputStream

            // DNS over TCP: 2 byte length + payload
            val lenBytes = ByteArray(2)
            lenBytes[0] = ((query.size shr 8) and 0xFF).toByte()
            lenBytes[1] = (query.size and 0xFF).toByte()

            out.write(lenBytes)
            out.write(query)
            out.flush()

            // Read Response
            // First 2 bytes length
            val respLenBytes = ByteArray(2)
            if (readFully(`in`, respLenBytes) == 2) {
                val respLen = ((respLenBytes[0].toInt() and 0xFF) shl 8) or (respLenBytes[1].toInt() and 0xFF)
                val response = ByteArray(respLen)
                if (readFully(`in`, response) == respLen) {
                    sendResponse(srcIp, srcPort, dstIp, dstPort, response)
                }
            }
        } catch (e: Exception) {
            logger("DNS Failed: ${e.message}")
        } finally {
            try { channel?.disconnect() } catch (e: Exception) {}
        }
    }

    private fun readFully(`in`: InputStream, buffer: ByteArray): Int {
        var offset = 0
        while (offset < buffer.size) {
            val read = `in`.read(buffer, offset, buffer.size - offset)
            if (read == -1) break
            offset += read
        }
        return offset
    }

    private fun sendResponse(srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int, response: ByteArray) {
        val totalLen = 20 + 8 + response.size // IP + UDP + Data
        val buffer = ByteBuffer.allocate(totalLen)

        // IPv4
        buffer.put(0, 0x45.toByte())
        buffer.put(1, 0.toByte())
        buffer.putShort(2, totalLen.toShort())
        buffer.putShort(4, 0.toShort())
        buffer.putShort(6, 0.toShort()) // No DF needed for DNS usually
        buffer.put(8, 64.toByte())
        buffer.put(9, Packet.PROTOCOL_UDP.toByte())
        buffer.putShort(10, 0.toShort())

        buffer.putInt(12, dstIp) // Src IP (Server) -> Dst IP (Client)
        buffer.putInt(16, srcIp) // Dst IP (Client) -> Src IP (Server)
        Packet.updateIPChecksum(buffer, 0, 20)

        // UDP
        buffer.putShort(20, dstPort.toShort())
        buffer.putShort(22, srcPort.toShort())
        buffer.putShort(24, (8 + response.size).toShort())
        buffer.putShort(26, 0.toShort()) // Checksum

        buffer.position(28)
        buffer.put(response)

        Packet.calculateUDPChecksum(buffer, 20, totalLen, dstIp, srcIp)
        tun2Socks.writePacket(buffer, totalLen)
    }
}
