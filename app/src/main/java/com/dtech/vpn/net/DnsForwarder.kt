package com.dtech.vpn.net

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.DataInputStream
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

class DnsForwarder(
    private val tun2Socks: Tun2Socks,
    private val session: Session,
    private val dnsServer: String,
    private val logger: (String) -> Unit
) {
    private val executor = Executors.newCachedThreadPool()
    private val transactionIdGen = AtomicInteger(1)
    private var isRunning = false

    fun start() {
        if (isRunning) return
        isRunning = true

        // Trigger self-test immediately
        executor.submit {
            try {
                sendSelfTestQuery()
            } catch (e: Exception) {
                logger("DNS: Self-test failed: ${e.message}")
            }
        }
    }

    fun stop() {
        isRunning = false
        executor.shutdownNow()
    }

    fun processPacket(buffer: ByteBuffer, ipHeaderLen: Int, udpHeaderLen: Int, payloadLen: Int) {
        if (!isRunning || !session.isConnected) return

        val srcIp = Packet.getIPSrcInt(buffer)
        val dstIp = Packet.getIPDstInt(buffer)
        val srcPort = Packet.getUdpSrcPort(buffer, ipHeaderLen)
        val dstPort = Packet.getUdpDstPort(buffer, ipHeaderLen)

        // Extract DNS Query
        val query = ByteArray(payloadLen)
        buffer.position(ipHeaderLen + udpHeaderLen)
        buffer.get(query)

        executor.submit {
            handleQuery(srcIp, srcPort, dstIp, dstPort, query)
        }
    }

    private fun handleQuery(srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int, query: ByteArray) {
        var channel: ChannelDirectTCPIP? = null
        try {
            // 1. Open new channel
            channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(dnsServer)
            channel.setPort(53)
            channel.connect(10000)

            val out = channel.outputStream
            val inStream = DataInputStream(channel.inputStream)

            // 2. Send Query
            val len = query.size
            out.write((len shr 8) and 0xFF)
            out.write(len and 0xFF)
            out.write(query)
            out.flush()
            logger("DNS: Query sent (len=$len)")

            // 3. Read Response
            val respLen = inStream.readUnsignedShort()
            if (respLen > 0) {
                val response = ByteArray(respLen)
                inStream.readFully(response)
                logger("DNS: Response received")

                // 4. Send back to TUN
                sendResponseToTun(srcIp, srcPort, dstIp, dstPort, response)
            }

        } catch (e: Exception) {
            logger("DNS Query Failed: ${e.message}")
        } finally {
            try { channel?.disconnect() } catch (_: Exception) {}
        }
    }

    private fun sendSelfTestQuery() {
        // ID = 0 for self-test
        val query = byteArrayOf(
            // Header
            0x00, 0x00, // ID=0
            0x01, 0x00, // Flags: Std Query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // QNAME: google.com
            0x06, 'g'.code.toByte(), 'o'.code.toByte(), 'o'.code.toByte(), 'g'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00,
            // QTYPE: A (1)
            0x00, 0x01,
            // QCLASS: IN (1)
            0x00, 0x01
        )

        var channel: ChannelDirectTCPIP? = null
        try {
            channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(dnsServer)
            channel.setPort(53)
            channel.connect(10000)

            val out = channel.outputStream
            val inStream = DataInputStream(channel.inputStream)

            val len = query.size
            out.write((len shr 8) and 0xFF)
            out.write(len and 0xFF)
            out.write(query)
            out.flush()

            val respLen = inStream.readUnsignedShort()
            if (respLen > 0) {
                val response = ByteArray(respLen)
                inStream.readFully(response)

                // Check if ID is 0
                val id = getShort(response, 0).toInt() and 0xFFFF
                if (id == 0) {
                    logger("DNS: Self-test passed. Ready.")
                    tun2Socks.setDnsReady(true)
                }
            }
        } catch (e: Exception) {
            logger("DNS Self-Test Failed: ${e.message}")
        } finally {
            try { channel?.disconnect() } catch (_: Exception) {}
        }
    }

    private fun sendResponseToTun(srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int, response: ByteArray) {
        val totalLen = 20 + 8 + response.size // IP + UDP + Data
        val buffer = ByteBuffer.allocate(totalLen)

        // IPv4 Header
        buffer.put(0, 0x45.toByte())
        buffer.put(1, 0.toByte())
        buffer.putShort(2, totalLen.toShort())
        buffer.putShort(4, 0.toShort())
        buffer.putShort(6, 0.toShort())
        buffer.put(8, 64.toByte()) // TTL
        buffer.put(9, Packet.PROTOCOL_UDP.toByte())
        buffer.putShort(10, 0.toShort()) // Checksum placeholder

        // Swap Src/Dst for response
        buffer.putInt(12, dstIp) // Server IP
        buffer.putInt(16, srcIp) // Client IP
        Packet.updateIPChecksum(buffer, 0, 20)

        // UDP Header
        buffer.putShort(20, dstPort.toShort())
        buffer.putShort(22, srcPort.toShort())
        buffer.putShort(24, (8 + response.size).toShort())
        buffer.putShort(26, 0.toShort()) // Checksum

        buffer.position(28)
        buffer.put(response)

        Packet.calculateUDPChecksum(buffer, 20, totalLen, dstIp, srcIp)
        tun2Socks.writePacket(buffer, totalLen)
    }

    private fun getShort(b: ByteArray, off: Int): Short {
        return (((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)).toShort()
    }
}
