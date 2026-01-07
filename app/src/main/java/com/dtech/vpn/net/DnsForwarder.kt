package com.dtech.vpn.net

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.DataInputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class DnsForwarder(
    private val tun2Socks: Tun2Socks,
    private val session: Session,
    private val logger: (String) -> Unit
) {
    private var channel: ChannelDirectTCPIP? = null
    private var out: OutputStream? = null
    private var inStream: DataInputStream? = null
    private var isRunning = false
    private val lock = Any()

    // UDPGW Configuration
    private val useUdpGw = true // As requested by user "Enable UDPGW"
    private val udpGwHost = "127.0.0.1"
    private val udpGwPort = 7300

    private val pendingQueries = ConcurrentHashMap<Int, QueryMetadata>()
    private val transactionIdGen = AtomicInteger(1)

    data class QueryMetadata(
        val srcIp: Int,
        val srcPort: Int,
        val originalId: Short
    )

    fun start() {
        if (isRunning) return
        isRunning = true
        Thread { connectAndLoop() }.start()
    }

    fun stop() {
        isRunning = false
        closeChannel()
    }

    private fun connectAndLoop() {
        while (isRunning && session.isConnected) {
            try {
                if (useUdpGw) {
                    logger("UDPGW: Connecting to $udpGwHost:$udpGwPort...")
                } else {
                    logger("DNS: Connecting persistent channel to 8.8.8.8:53...")
                }

                // Open Channel
                val newChannel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                if (useUdpGw) {
                    newChannel.setHost(udpGwHost)
                    newChannel.setPort(udpGwPort)
                } else {
                    newChannel.setHost("8.8.8.8")
                    newChannel.setPort(53)
                }
                newChannel.connect(10000)

                synchronized(lock) {
                    channel = newChannel
                    out = newChannel.outputStream
                    inStream = DataInputStream(newChannel.inputStream)
                }

                logger(if (useUdpGw) "UDPGW: Channel opened." else "DNS: Channel opened.")

                if (!useUdpGw) {
                    // Send self-test query asynchronously only for direct DNS
                    sendSelfTestQuery()
                } else {
                    // For UDPGW, we assume it works or we can trigger a self-test?
                    // Let's mark DNS as ready immediately or send a test packet.
                    // For now, let's just mark ready to avoid blocking.
                    tun2Socks.setDnsReady(true)
                }

                // Response Reader Loop
                val currentIn = inStream
                while (isRunning && channel?.isConnected == true) {
                    // Read Length (2 bytes)
                    // UDPGW uses Little Endian. DNS-over-TCP uses Big Endian.
                    val len = try {
                        if (useUdpGw) {
                            readShortLE(currentIn!!)
                        } else {
                            currentIn?.readUnsignedShort() ?: -1
                        }
                    } catch (e: Exception) {
                        -1
                    }

                    if (len <= 0) {
                        logger("Stream closed or Invalid Length ($len)")
                        break
                    }

                    // Read Packet
                    val buffer = ByteArray(len)
                    try {
                        currentIn?.readFully(buffer)
                        if (useUdpGw) {
                            processUdpGwResponse(buffer)
                        } else {
                            processDnsOverTcpResponse(buffer)
                        }
                    } catch (e: Exception) {
                        logger("Read Payload Error: ${e.message}")
                        break
                    }
                }
            } catch (e: Exception) {
                logger("Channel Error: ${e.message}")
                try { Thread.sleep(2000) } catch (_: Exception) {}
            } finally {
                logger("Channel loop ended. Restarting if needed...")
                tun2Socks.setDnsReady(false)
                closeChannel()
            }
        }
        logger("Handler stopped.")
    }

    private fun readShortLE(input: DataInputStream): Int {
        val b1 = input.read()
        val b2 = input.read()
        if (b1 == -1 || b2 == -1) return -1
        return (b1 and 0xFF) or ((b2 and 0xFF) shl 8)
    }

    private fun sendSelfTestQuery() {
        // Only for DNS over TCP mode
        val query = byteArrayOf(
            0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, 'g'.code.toByte(), 'o'.code.toByte(), 'o'.code.toByte(), 'g'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00, 0x00, 0x01, 0x00, 0x01
        )
        sendOverTcp(query)
    }

    private fun closeChannel() {
        try { out?.close() } catch (_: Exception) {}
        try { inStream?.close() } catch (_: Exception) {}
        try { channel?.disconnect() } catch (_: Exception) {}
        channel = null
    }

    fun processPacket(buffer: ByteBuffer, ipHeaderLen: Int, udpHeaderLen: Int, payloadLen: Int) {
        if (channel == null || !channel!!.isConnected) {
            return
        }

        if (useUdpGw) {
             // For DNS packets, we still want to map them if possible to handle NAT correctly for DNS
             // Since we know this is a DNS forwarder (only called for port 53 in Tun2Socks),
             // we can use the ID mapping strategy.

             storeQueryMetadata(buffer, ipHeaderLen, udpHeaderLen)

             // Extract Payload (DNS Query with rewritten ID)
             val data = ByteArray(payloadLen)
             buffer.position(ipHeaderLen + udpHeaderLen)
             buffer.get(data)

            val dstIp = Packet.getIPDstInt(buffer)
            val dstPort = Packet.getUdpDstPort(buffer, ipHeaderLen)
            sendOverUdpGw(dstIp, dstPort, data)
        } else {
            // Mapping logic for DNS over TCP
             storeQueryMetadata(buffer, ipHeaderLen, udpHeaderLen)
             val data = ByteArray(payloadLen)
             buffer.position(ipHeaderLen + udpHeaderLen)
             buffer.get(data)
             sendOverTcp(data)
        }
    }

    // Called from processPacket (Sender)
    private fun storeQueryMetadata(buffer: ByteBuffer, ipHeaderLen: Int, udpHeaderLen: Int): Int {
         val srcIp = Packet.getIPSrcInt(buffer)
         val srcPort = Packet.getUdpSrcPort(buffer, ipHeaderLen)

         // Parse Query ID
         buffer.position(ipHeaderLen + udpHeaderLen)
         // We need to peek, not consume yet
         val idHigh = buffer.get(ipHeaderLen + udpHeaderLen).toInt() and 0xFF
         val idLow = buffer.get(ipHeaderLen + udpHeaderLen + 1).toInt() and 0xFF
         val originalId = ((idHigh shl 8) or idLow).toShort()

         // Generate New ID
         var newId = transactionIdGen.getAndIncrement() and 0xFFFF
         if (newId == 0) newId = transactionIdGen.getAndIncrement() and 0xFFFF

         pendingQueries[newId] = QueryMetadata(srcIp, srcPort, originalId)

         // Rewrite ID in buffer
         buffer.put(ipHeaderLen + udpHeaderLen, ((newId shr 8) and 0xFF).toByte())
         buffer.put(ipHeaderLen + udpHeaderLen + 1, (newId and 0xFF).toByte())

         return newId
    }

    private fun sendOverUdpGw(dstIp: Int, dstPort: Int, payload: ByteArray) {
        synchronized(lock) {
            try {
                if (out != null) {
                    // BadVPN UDPGW Packet:
                    // Header: [Len (2 LE)]
                    // Body: [Flag(0)] [AddrType(1)] [Port(2 BE)] [IP(4 BE)] [Payload]

                    val bodyLen = 1 + 1 + 2 + 4 + payload.size

                    // Write Length (LE)
                    out?.write(bodyLen and 0xFF)
                    out?.write((bodyLen shr 8) and 0xFF)

                    // Write Body
                    out?.write(0) // Flag
                    out?.write(1) // AddrType IPv4

                    // Port (BE)
                    out?.write((dstPort shr 8) and 0xFF)
                    out?.write(dstPort and 0xFF)

                    // IP (BE)
                    out?.write((dstIp shr 24) and 0xFF)
                    out?.write((dstIp shr 16) and 0xFF)
                    out?.write((dstIp shr 8) and 0xFF)
                    out?.write(dstIp and 0xFF)

                    // Payload
                    out?.write(payload)
                    out?.flush()
                    // logger("UDPGW: Sent packet len=${payload.size}")
                }
            } catch (e: Exception) {
                logger("UDPGW Send failed: ${e.message}")
                closeChannel()
            }
        }
    }

    private fun processUdpGwResponse(data: ByteArray) {
        // Body: [Flag] [AddrType] [Port] [IP] [Payload]
        if (data.size < 8) return

        // Parse Header
        // val flag = data[0]
        // val addrType = data[1]

        val srcPort = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        val srcIp = ((data[4].toInt() and 0xFF) shl 24) or
                    ((data[5].toInt() and 0xFF) shl 16) or
                    ((data[6].toInt() and 0xFF) shl 8) or
                    (data[7].toInt() and 0xFF)

        val payloadLen = data.size - 8
        if (payloadLen <= 0) return

        val payload = ByteArray(payloadLen)
        System.arraycopy(data, 8, payload, 0, payloadLen)

        restoreMapAndSend(srcIp, srcPort, payload)
    }

    private fun restoreMapAndSend(serverIp: Int, serverPort: Int, response: ByteArray) {
        if (response.size < 2) return

        val id = (((response[0].toInt() and 0xFF) shl 8) or (response[1].toInt() and 0xFF))

        val meta = pendingQueries.remove(id)
        if (meta == null) {
            // logger("DNS: Unknown ID $id")
            return
        }

        // Restore ID
        response[0] = ((meta.originalId.toInt() shr 8) and 0xFF).toByte()
        response[1] = (meta.originalId.toInt() and 0xFF).toByte()

        sendResponseToTun(meta, serverIp, serverPort, response)
    }

    private fun sendResponseToTun(meta: QueryMetadata, serverIp: Int, serverPort: Int, response: ByteArray) {
        val totalLen = 20 + 8 + response.size
        val buffer = ByteBuffer.allocate(totalLen)

        // IPv4 Header
        buffer.put(0, 0x45.toByte())
        buffer.put(1, 0.toByte())
        buffer.putShort(2, totalLen.toShort())
        buffer.putShort(4, 0.toShort())
        buffer.putShort(6, 0.toShort())
        buffer.put(8, 64.toByte()) // TTL
        buffer.put(9, Packet.PROTOCOL_UDP.toByte())
        buffer.putShort(10, 0.toShort()) // Checksum

        buffer.putInt(12, serverIp)
        buffer.putInt(16, meta.srcIp)
        Packet.updateIPChecksum(buffer, 0, 20)

        // UDP Header
        buffer.putShort(20, serverPort.toShort())
        buffer.putShort(22, meta.srcPort.toShort())
        buffer.putShort(24, (8 + response.size).toShort())
        buffer.putShort(26, 0.toShort())

        buffer.position(28)
        buffer.put(response)

        Packet.calculateUDPChecksum(buffer, 20, totalLen, serverIp, meta.srcIp)
        tun2Socks.writePacket(buffer, totalLen)
    }

    // DNS Over TCP support (fallback logic)
    private fun sendOverTcp(query: ByteArray) {
        synchronized(lock) {
             try {
                 if (out != null) {
                     val len = query.size
                     out?.write((len shr 8) and 0xFF)
                     out?.write(len and 0xFF)
                     out?.write(query)
                     out?.flush()
                 }
             } catch(e: Exception) {
                 logger("DNS Send failed: ${e.message}")
                 closeChannel()
             }
        }
    }

    private fun processDnsOverTcpResponse(buffer: ByteArray) {
         // Assuming buffer is just the payload
         restoreMapAndSend(0x08080808.toInt(), 53, buffer) // Default to 8.8.8.8:53 for response source
    }
}
