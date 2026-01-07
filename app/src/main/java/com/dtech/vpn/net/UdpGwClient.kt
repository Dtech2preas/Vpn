package com.dtech.vpn.net

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.DataInputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

class UdpGwClient(
    private val tun2Socks: Tun2Socks,
    private val session: Session,
    private val port: Int,
    private val customDns: String,
    private val logger: (String) -> Unit
) {
    private var channel: ChannelDirectTCPIP? = null
    private var out: OutputStream? = null
    private var inStream: DataInputStream? = null
    private val isRunning = AtomicBoolean(false)
    private val lock = Any()

    // ConId -> Connection Metadata
    private val connections = ConcurrentHashMap<Int, UdpConnection>()

    // Key: "SrcIP:SrcPort" -> ConId
    private val flowToConId = ConcurrentHashMap<String, Int>()

    // Pool of free ConIDs (1..65535)
    // For simplicity, we can just use a counter and wrap around, or check collision.
    // Given the max connections, simple increments are likely fine for this scope.
    private var nextConId = 1

    companion object {
        const val FLAG_KEEPALIVE = 0x01
        const val FLAG_REBIND = 0x02
        const val FLAG_DNS = 0x04 // Note: Not using badvpn specific flags for now, sticking to basic header

        // Protocol Max Packet Size
        const val MAX_PACKET_SIZE = 4096
    }

    data class UdpConnection(
        val conId: Int,
        val clientIp: Int,
        val clientPort: Int,
        val originalServerIp: Int, // The IP the client THINKS it is sending to
        val originalServerPort: Int,
        val actualServerIp: Int, // The IP we are actually sending to (via UDPGW)
        val actualServerPort: Int,
        var lastActivity: Long
    )

    fun start() {
        if (isRunning.get()) return
        isRunning.set(true)
        Thread { connectAndLoop() }.start()

        // Cleanup thread
        Thread { cleanupLoop() }.start()
    }

    fun stop() {
        isRunning.set(false)
        closeChannel()
    }

    private fun connectAndLoop() {
        while (isRunning.get() && session.isConnected) {
            try {
                logger("UDPGW: Connecting to 127.0.0.1:$port...")

                val newChannel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                newChannel.setHost("127.0.0.1")
                newChannel.setPort(port)
                newChannel.connect(10000)

                synchronized(lock) {
                    channel = newChannel
                    out = newChannel.outputStream
                    inStream = DataInputStream(newChannel.inputStream)
                }

                logger("UDPGW: Connected.")

                // Send Keepalives or just wait for data?
                // badvpn-tun2socks sends keepalives.

                val currentIn = inStream
                while (isRunning.get() && channel?.isConnected == true) {
                    // Read Packet Length (2 bytes Little Endian)
                    val lenLow = currentIn?.read() ?: -1
                    val lenHigh = currentIn?.read() ?: -1

                    if (lenLow < 0 || lenHigh < 0) break

                    val len = (lenLow and 0xFF) or ((lenHigh and 0xFF) shl 8)

                    if (len > 0) {
                        val buffer = ByteArray(len)
                        currentIn?.readFully(buffer)
                        processIncomingFrame(buffer)
                    }
                }

            } catch (e: Exception) {
                logger("UDPGW Error: ${e.message}")
                try { Thread.sleep(2000) } catch (_: Exception) {}
            } finally {
                closeChannel()
            }
        }
    }

    private fun closeChannel() {
        try { out?.close() } catch (_: Exception) {}
        try { inStream?.close() } catch (_: Exception) {}
        try { channel?.disconnect() } catch (_: Exception) {}
        channel = null
    }

    fun processPacket(buffer: ByteBuffer, length: Int) {
        if (channel == null || !channel!!.isConnected) return

        val ipHeaderLen = Packet.getIPHeaderLength(buffer)
        val srcIp = Packet.getIPSrcInt(buffer)
        val dstIp = Packet.getIPDstInt(buffer)
        val srcPort = Packet.getUdpSrcPort(buffer, ipHeaderLen)
        val dstPort = Packet.getUdpDstPort(buffer, ipHeaderLen)
        val payloadLen = length - ipHeaderLen - 8

        // Flow Key
        val key = "$srcIp:$srcPort"

        var conId = flowToConId[key]
        var connection = if (conId != null) connections[conId] else null

        // Check if destination changed (re-bind needed? or just new flow?)
        // If the same client sends to a different server, we treat it as the SAME flow in UDPGW?
        // badvpn-tun2socks maps (ClientIP, ClientPort, RemoteIP, RemotePort) -> ConID.
        // It's specific to the 4-tuple.
        // So key should include destination.
        val fullKey = "$srcIp:$srcPort->$dstIp:$dstPort"

        // Wait, if I change destination for DNS, I need to be careful.

        var effectiveDstIp = dstIp
        var effectiveDstPort = dstPort

        // DNS Override
        if (dstPort == 53 && customDns.isNotEmpty()) {
            try {
                // Parse custom DNS IP
                // Simple parsing for IPv4
                val parts = customDns.split(".")
                if (parts.size == 4) {
                     effectiveDstIp = (parts[0].toInt() shl 24) or (parts[1].toInt() shl 16) or (parts[2].toInt() shl 8) or parts[3].toInt()
                }
            } catch (e: Exception) {
                // Ignore, stick to original
            }
        }

        // Revised Key strategy: 5-tuple
        val flowKey = "$srcIp:$srcPort->$dstIp:$dstPort"
        // Note: We key off the ORIGINAL destination, so we can map back correctly.

        conId = flowToConId[flowKey]
        connection = if (conId != null) connections[conId] else null

        if (connection == null) {
            conId = allocateConId()
            connection = UdpConnection(
                conId = conId,
                clientIp = srcIp,
                clientPort = srcPort,
                originalServerIp = dstIp,
                originalServerPort = dstPort,
                actualServerIp = effectiveDstIp,
                actualServerPort = effectiveDstPort,
                lastActivity = System.currentTimeMillis()
            )
            connections[conId] = connection
            flowToConId[flowKey] = conId
        } else {
            connection.lastActivity = System.currentTimeMillis()
        }

        // Encapsulate and Send
        val payload = ByteArray(payloadLen)
        buffer.position(ipHeaderLen + 8)
        buffer.get(payload)

        sendUdpGwPacket(connection, payload)
    }

    private fun sendUdpGwPacket(conn: UdpConnection, payload: ByteArray) {
        // Construct Header
        // Flags (1) + ConID (2 LE) + IP (4 BE) + Port (2 BE) + Data
        val frameLen = 1 + 2 + 4 + 2 + payload.size

        val frame = ByteArray(frameLen)
        val bb = ByteBuffer.wrap(frame)

        // Flags: 0
        bb.put(0.toByte())

        // ConID: Little Endian
        bb.put((conn.conId and 0xFF).toByte())
        bb.put(((conn.conId shr 8) and 0xFF).toByte())

        // Address: Server IP/Port we want to send TO (Actual)
        bb.putInt(conn.actualServerIp) // BE by default
        bb.putShort(conn.actualServerPort.toShort()) // BE by default

        bb.put(payload)

        // Send over TCP Stream
        // Length Prefix (2 LE) + Frame
        synchronized(lock) {
            try {
                out?.write(frameLen and 0xFF)
                out?.write((frameLen shr 8) and 0xFF)
                out?.write(frame)
                out?.flush()
            } catch (e: Exception) {
                logger("UDPGW Send Failed: ${e.message}")
                closeChannel()
            }
        }
    }

    private fun processIncomingFrame(frame: ByteArray) {
        if (frame.size < 3) return // Min header size

        val bb = ByteBuffer.wrap(frame)
        val flags = bb.get()

        // ConID: Little Endian
        val conIdLow = bb.get().toInt() and 0xFF
        val conIdHigh = bb.get().toInt() and 0xFF
        val conId = conIdLow or (conIdHigh shl 8)

        val conn = connections[conId] ?: return
        conn.lastActivity = System.currentTimeMillis()

        // Address Parsing
        // The protocol sends back the source address of the packet (the server).
        // IPv4 (4+2) or IPv6 (16+2)
        // We need to check flags or length?
        // Standard badvpn-udpgw usually returns standard frames.
        // Assuming IPv4 for now as per project constraints.
        // IP (4) + Port (2)
        if (frame.size < 1 + 2 + 4 + 2) return

        val serverIp = bb.getInt()
        val serverPort = bb.getShort().toInt() and 0xFFFF

        // Data follows
        val dataLen = frame.size - bb.position()
        if (dataLen < 0) return
        val data = ByteArray(dataLen)
        bb.get(data)

        // Inject to TUN
        // Src: Original Server IP/Port (conn.originalServerIp)
        // Dst: Client IP/Port (conn.clientIp)
        // Note: The `serverIp` in the frame is the `actualServerIp` (e.g. 1.1.1.1).
        // We must rewrite it to `originalServerIp` (e.g. 8.8.8.8) so the app accepts it.

        injectToTun(conn, data)
    }

    private fun injectToTun(conn: UdpConnection, data: ByteArray) {
        val totalLen = 20 + 8 + data.size
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

        buffer.putInt(12, conn.originalServerIp) // Src: Server
        buffer.putInt(16, conn.clientIp) // Dst: Client
        Packet.updateIPChecksum(buffer, 0, 20)

        // UDP Header
        buffer.putShort(20, conn.originalServerPort.toShort())
        buffer.putShort(22, conn.clientPort.toShort())
        buffer.putShort(24, (8 + data.size).toShort())
        buffer.putShort(26, 0.toShort()) // Checksum

        buffer.position(28)
        buffer.put(data)

        Packet.calculateUDPChecksum(buffer, 20, totalLen, conn.originalServerIp, conn.clientIp)
        tun2Socks.writePacket(buffer, totalLen)
    }

    private fun allocateConId(): Int {
        // Naive allocation
        var id = nextConId++
        if (nextConId > 65535) nextConId = 1
        return id
    }

    private fun cleanupLoop() {
        while (isRunning.get()) {
            try {
                Thread.sleep(30000)
                val now = System.currentTimeMillis()
                val iterator = connections.entries.iterator()
                while (iterator.hasNext()) {
                    val entry = iterator.next()
                    if (now - entry.value.lastActivity > 60000) { // 60s timeout
                        iterator.remove()
                        // Also remove from flow map. Ideally we store key in connection to remove it easily.
                        // For now, full scan or just let flow map grow? Flow map needs to be cleaned.
                        removeFromFlowMap(entry.key)
                    }
                }
            } catch (e: Exception) {}
        }
    }

    private fun removeFromFlowMap(conId: Int) {
        val keysToRemove = mutableListOf<String>()
        flowToConId.forEach { (k, v) ->
            if (v == conId) keysToRemove.add(k)
        }
        keysToRemove.forEach { flowToConId.remove(it) }
    }
}
