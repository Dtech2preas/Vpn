package com.dtech.vpn.net

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

class TcpConn(
    val session: Session,
    val sourceIp: String,
    val sourcePort: Int,
    val destIp: String,
    val destPort: Int,
    val initialSeqNum: Long,
    val tunWriter: OutputStream,
    val onClosed: (TcpConn) -> Unit
) {
    private var channel: ChannelDirectTCPIP? = null
    private var inStream: InputStream? = null
    private var outStream: OutputStream? = null
    private val isClosed = AtomicBoolean(false)

    // Minimal TCP State
    var mySeq: Long = 0 // Sent to Android (remote sequence)
    var myAck: Long = initialSeqNum + 1 // Expected from Android (remote ack). Syn consumes 1.

    fun start() {
        Thread {
            try {
                if (!session.isConnected) throw Exception("Session not connected")

                channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                channel!!.setHost(destIp)
                channel!!.setPort(destPort)
                channel!!.connect(10000)

                inStream = channel!!.inputStream
                outStream = channel!!.outputStream

                // Connection established with remote server.
                // Now we must complete the TCP 3-way handshake with the Android App (via TUN).
                // Android sent SYN. We need to send SYN-ACK.

                // Randomize initial Sequence Number (ISN)
                mySeq = (System.currentTimeMillis() / 1000)

                sendSynAck()

                // Start reading from SSH and forwarding to TUN
                readLoop()

            } catch (e: Exception) {
                e.printStackTrace()
                close()
            }
        }.start()
    }

    fun sendData(payload: ByteArray, offset: Int, length: Int, seq: Long) {
        if (isClosed.get()) return
        try {
            // Update ACK tracker (simplistic)
            myAck = seq + length
            outStream?.write(payload, offset, length)
            outStream?.flush()

            // We should ACK this data to Android immediately or piggyback.
            // For simplicity, send an empty ACK packet.
            sendAck()
        } catch (e: Exception) {
            close()
        }
    }

    private fun readLoop() {
        val buffer = ByteArray(8192)
        try {
            while (!isClosed.get()) {
                val read = inStream?.read(buffer) ?: -1
                if (read == -1) break

                // Received data from Remote Server (via SSH).
                // Encapsulate in TCP/IP and write to TUN.
                sendTcpPacket(buffer, 0, read, isPsh = true)
            }
        } catch (e: Exception) {
            // Log?
        } finally {
            close()
        }
    }

    private fun sendSynAck() {
        // SYN-ACK: Flags = SYN | ACK
        // Seq = mySeq
        // Ack = myAck (Android's Seq + 1)
        sendTcpPacket(ByteArray(0), 0, 0, isSyn = true, isAck = true)
        mySeq++ // SYN consumes 1 sequence number
    }

    private fun sendAck() {
         sendTcpPacket(ByteArray(0), 0, 0, isAck = true)
    }

    private fun sendTcpPacket(data: ByteArray, offset: Int, len: Int, isSyn: Boolean = false, isAck: Boolean = false, isPsh: Boolean = false, isFin: Boolean = false) {
        // Construct IPv4 + TCP packet
        // Total Length = 20 (IP) + 20 (TCP) + len
        val totalLen = 40 + len
        val buffer = ByteBuffer.allocate(totalLen)

        // --- IP Header (20 bytes) ---
        buffer.put(0x45.toByte()) // Version 4, IHL 5
        buffer.put(0x00.toByte()) // TOS
        buffer.putShort(totalLen.toShort()) // Total Length
        buffer.putShort(0.toShort()) // ID
        buffer.putShort(0x4000.toShort()) // Flags (DF) + Fragment Offset
        buffer.put(64.toByte()) // TTL
        buffer.put(6.toByte()) // Protocol (TCP)
        buffer.putShort(0.toShort()) // Checksum (0 for calculation)

        // Source IP (Remote Server IP -> We fake this to match what Android requested)
        // Android requested DestIP. So SrcIP of response MUST be DestIP.
        // Wait, destIp string to bytes...
        buffer.put(parseIp(destIp))
        // Dest IP (Android IP)
        buffer.put(parseIp(sourceIp))

        // Calc IP Checksum
        val ipChecksum = calculateChecksum(buffer.array(), 0, 20)
        buffer.putShort(10, ipChecksum.toShort())

        // --- TCP Header (20 bytes) ---
        buffer.putShort(destPort.toShort()) // Source Port (Remote Port)
        buffer.putShort(sourcePort.toShort()) // Dest Port (Android Port)
        buffer.putInt(mySeq.toInt()) // Sequence Number
        buffer.putInt(myAck.toInt()) // Acknowledge Number

        var flags = 0
        if (isFin) flags = flags or 0x01
        if (isSyn) flags = flags or 0x02
        if (isPsh) flags = flags or 0x08
        if (isAck) flags = flags or 0x10
        // Data Offset (5 words = 20 bytes) + Reserved + Flags
        buffer.putShort(((5 shl 12) or flags).toShort())

        buffer.putShort(65535.toShort()) // Window
        buffer.putShort(0.toShort()) // Checksum (0 for now)
        buffer.putShort(0.toShort()) // Urgent Pointer

        if (len > 0) {
            buffer.put(data, offset, len)
        }

        // Calc TCP Checksum (Pseudo-header + TCP Header + Data)
        val tcpLen = 20 + len
        val pseudoHeader = ByteBuffer.allocate(12 + tcpLen)
        pseudoHeader.put(parseIp(destIp)) // Source
        pseudoHeader.put(parseIp(sourceIp)) // Dest
        pseudoHeader.put(0.toByte())
        pseudoHeader.put(6.toByte()) // Protocol
        pseudoHeader.putShort(tcpLen.toShort())
        pseudoHeader.put(buffer.array(), 20, tcpLen) // TCP Header + Data

        val tcpChecksum = calculateChecksum(pseudoHeader.array(), 0, 12 + tcpLen)
        buffer.putShort(36, tcpChecksum.toShort())

        // Write to TUN
        synchronized(tunWriter) {
            try {
                tunWriter.write(buffer.array())
                // tunWriter.flush()
            } catch (e: Exception) {
                close()
            }
        }

        // Advance Sequence Number
        if (len > 0) {
            mySeq += len
        }
    }

    private fun parseIp(ip: String): ByteArray {
        val parts = ip.split(".")
        return byteArrayOf(
            parts[0].toInt().toByte(),
            parts[1].toInt().toByte(),
            parts[2].toInt().toByte(),
            parts[3].toInt().toByte()
        )
    }

    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        var len = length
        while (len > 1) {
            val current = (data[i].toInt() and 0xFF) shl 8 or (data[i + 1].toInt() and 0xFF)
            sum += current
            i += 2
            len -= 2
        }
        if (len > 0) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while ((sum shr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    fun close() {
        if (isClosed.compareAndSet(false, true)) {
            try { inStream?.close() } catch (e: Exception) {}
            try { outStream?.close() } catch (e: Exception) {}
            try { channel?.disconnect() } catch (e: Exception) {}
            onClosed(this)
        }
    }
}
