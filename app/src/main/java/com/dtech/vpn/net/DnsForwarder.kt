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
    private val pendingQueries = ConcurrentHashMap<Int, QueryMetadata>()
    private val transactionIdGen = AtomicInteger(1)
    private var isRunning = false
    private val lock = Any()

    data class QueryMetadata(
        val srcIp: Int,
        val srcPort: Int,
        val dstIp: Int,
        val dstPort: Int,
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
                // Persistent connection logic
                logger("DNS: Connecting persistent channel to 8.8.8.8:53...")

                // Open Channel
                val newChannel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                newChannel.setHost("8.8.8.8")
                newChannel.setPort(53)
                newChannel.connect(10000)

                synchronized(lock) {
                    channel = newChannel
                    out = newChannel.outputStream
                    inStream = DataInputStream(newChannel.inputStream)
                }

                logger("DNS: Channel opened.")

                // Perform mandatory self-test before declaring ready
                if (performSelfTest()) {
                    logger("DNS: Self-test passed. Ready.")
                    tun2Socks.setDnsReady(true)
                } else {
                    logger("DNS: Self-test failed.")
                    closeChannel()
                    // Retry loop will wait 2s below
                    throw Exception("Self-test failed")
                }

                // Response Reader Loop
                val currentIn = inStream
                while (isRunning && channel?.isConnected == true) {
                    // Read Length (2 bytes)
                    // If stream closes, this throws or returns EOF
                    val len = try {
                        currentIn?.readUnsignedShort() ?: -1
                    } catch (e: Exception) { -1 }

                    if (len <= 0) break

                    // Read Payload
                    val buffer = ByteArray(len)
                    try {
                        currentIn?.readFully(buffer)
                        processResponse(buffer)
                    } catch (e: Exception) {
                        break
                    }
                }
            } catch (e: Exception) {
                logger("DNS Channel Error/Closed: ${e.message}")
            } finally {
                tun2Socks.setDnsReady(false)
                closeChannel()
                if (isRunning) {
                     try { Thread.sleep(2000) } catch (_: Exception) {}
                }
            }
        }
        logger("DNS: Handler stopped.")
    }

    private fun performSelfTest(): Boolean {
        // Simple query for google.com or similar.
        // We construct a raw DNS query for "google.com" (A record).
        // Header: ID=1234, Flags=0100 (Standard Query), QDCOUNT=1, AN=0, NS=0, AR=0
        // Query: 6google3com0, Type=1 (A), Class=1 (IN)
        val testId = 12345
        val query = byteArrayOf(
            // Header
            (testId shr 8).toByte(), (testId and 0xFF).toByte(), // ID
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

        val latch = java.util.concurrent.CountDownLatch(1)
        var success = false

        // We temporarily register this ID to intercept the response
        // Use a negative ID or special handling?
        // Our map key is Int, so we can use the testId directly if we bypass the generator.

        // We need a special 'TestQueryMetadata' or just handle it in processResponse?
        // Let's use the standard flow but with a dummy metadata
        val dummyMeta = QueryMetadata(0,0,0,0, testId.toShort())

        // IMPORTANT: The processResponse removes from map. We need to know if it was ours.
        // We can check if pendingQueries contains it.
        // Wait, 'processPacket' generates a NEW ID.
        // For self test, we want to bypass 'processPacket' and send directly.

        // We need to inject into pendingQueries with the ID we send.
        pendingQueries[testId] = dummyMeta

        try {
            sendOverTcp(query)

            // Wait for response
            // processResponse will remove it from map and normally try to send to TUN.
            // If srcIp is 0, sendResponseToTun should probably ignore it or we handle it here.
            // But processResponse runs on this same thread? NO.
            // connectAndLoop IS the reader thread (after test).
            // Ah, I cannot block here waiting for the reader loop because I AM the reader loop context (or I am blocking it).
            // The reader loop STARTS after this test.
            // So how do I read the response?

            // I must read the response HERE manually for the test.
            val currentIn = inStream ?: return false
            val len = currentIn.readUnsignedShort()
            val buffer = ByteArray(len)
            currentIn.readFully(buffer)

            // Verify ID
            val respId = getShort(buffer, 0).toInt() and 0xFFFF
            if (respId == testId) {
                return true
            }
        } catch (e: Exception) {
            logger("DNS Self Test Error: ${e.message}")
        } finally {
            pendingQueries.remove(testId)
        }
        return false
    }

    private fun closeChannel() {
        try { out?.close() } catch (_: Exception) {}
        try { inStream?.close() } catch (_: Exception) {}
        try { channel?.disconnect() } catch (_: Exception) {}
        channel = null
    }

    fun processPacket(buffer: ByteBuffer, ipHeaderLen: Int, udpHeaderLen: Int, payloadLen: Int) {
        if (channel == null || !channel!!.isConnected) {
            // Drop packet if DNS is down
            return
        }

        val srcIp = Packet.getIPSrcInt(buffer)
        val dstIp = Packet.getIPDstInt(buffer)
        val srcPort = Packet.getUdpSrcPort(buffer, ipHeaderLen)
        val dstPort = Packet.getUdpDstPort(buffer, ipHeaderLen)

        // Extract DNS Query
        val query = ByteArray(payloadLen)
        buffer.position(ipHeaderLen + udpHeaderLen)
        buffer.get(query)

        // 1. Extract Original ID
        val originalId = getShort(query, 0)

        // 2. Generate New ID (Ensure it doesn't conflict with our test ID 12345 if we used that, but we only test at start)
        val newId = transactionIdGen.getAndIncrement() and 0xFFFF

        // 3. Store Mapping
        pendingQueries[newId] = QueryMetadata(srcIp, srcPort, dstIp, dstPort, originalId)

        // 4. Rewrite ID in query
        setShort(query, 0, newId.toShort())

        // 5. Send over TCP
        sendOverTcp(query)
    }

    private fun sendOverTcp(query: ByteArray) {
        synchronized(lock) {
            try {
                if (out != null) {
                    val len = query.size
                    out?.write((len shr 8) and 0xFF)
                    out?.write(len and 0xFF)
                    out?.write(query)
                    out?.flush()
                    logger("DNS: Query sent (len=${query.size})")
                }
            } catch (e: Exception) {
                logger("DNS: Send failed: ${e.message}")
                closeChannel()
            }
        }
    }

    private fun processResponse(response: ByteArray) {
        if (response.size < 2) return

        // 1. Extract ID
        val id = getShort(response, 0).toInt() and 0xFFFF

        // 2. Lookup Mapping
        val meta = pendingQueries.remove(id)
        if (meta == null) {
            return
        }

        logger("DNS: Response received")

        // 3. Restore Original ID
        setShort(response, 0, meta.originalId)

        // 4. Construct UDP Packet and inject to Tun
        // If it was a dummy meta (srcIp=0), we ignore (though self-test handles its own read)
        if (meta.srcIp != 0) {
            sendResponseToTun(meta, response)
        }
    }

    private fun sendResponseToTun(meta: QueryMetadata, response: ByteArray) {
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
        buffer.putInt(12, meta.dstIp) // Server IP
        buffer.putInt(16, meta.srcIp) // Client IP
        Packet.updateIPChecksum(buffer, 0, 20)

        // UDP Header
        buffer.putShort(20, meta.dstPort.toShort())
        buffer.putShort(22, meta.srcPort.toShort())
        buffer.putShort(24, (8 + response.size).toShort())
        buffer.putShort(26, 0.toShort()) // Checksum

        buffer.position(28)
        buffer.put(response)

        Packet.calculateUDPChecksum(buffer, 20, totalLen, meta.dstIp, meta.srcIp)
        tun2Socks.writePacket(buffer, totalLen)
    }

    private fun getShort(b: ByteArray, off: Int): Short {
        return (((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)).toShort()
    }

    private fun setShort(b: ByteArray, off: Int, value: Short) {
        b[off] = ((value.toInt() shr 8) and 0xFF).toByte()
        b[off + 1] = (value.toInt() and 0xFF).toByte()
    }
}
