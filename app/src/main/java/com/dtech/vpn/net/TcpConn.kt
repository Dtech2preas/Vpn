package com.dtech.vpn.net

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

class TcpConn(
    private val tun2Socks: Tun2Socks,
    private val key: String,
    private val session: Session,
    private val sourceIp: Int,
    private val sourcePort: Int,
    private val destIp: Int,
    private val destPort: Int,
    initialSeq: Long,
    private val logger: (String) -> Unit
) {

    private enum class State {
        CLOSED, SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT
    }

    @Volatile private var state = State.CLOSED
    @Volatile private var mySeq = 1000L // Random start
    @Volatile private var myAck = initialSeq + 1
    @Volatile private var peerSeq = initialSeq + 1

    private var channel: ChannelDirectTCPIP? = null
    private var sshIn: InputStream? = null
    private var sshOut: OutputStream? = null

    private val isRunning = AtomicBoolean(true)
    private val readThread = Thread { readLoop() }

    // Simplification: Standard Window Size
    private val WINDOW_SIZE = 65535

    init {
        // We received a SYN.
        state = State.SYN_RCVD
        sendSynAck()

        // Connect to SSH in background
        Thread {
            try {
                connectSsh()
            } catch (e: Exception) {
                logger("Connect failed for $key: ${e.message}")
                sendRst()
                close()
            }
        }.start()
    }

    private fun connectSsh() {
        if (state == State.CLOSED) return

        val dstIpStr = String.format("%d.%d.%d.%d",
            (destIp shr 24) and 0xFF,
            (destIp shr 16) and 0xFF,
            (destIp shr 8) and 0xFF,
            destIp and 0xFF)

        // logger("Opening SSH channel to $dstIpStr:$destPort")

        val ch = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
        ch.setHost(dstIpStr)
        ch.setPort(destPort)
        // Originator info (Source IP/Port) - helpful for some servers logs
        ch.setOrgIPAddress(String.format("%d.%d.%d.%d", (sourceIp shr 24) and 0xFF, (sourceIp shr 16) and 0xFF, (sourceIp shr 8) and 0xFF, sourceIp and 0xFF))
        ch.setOrgPort(sourcePort)

        ch.connect(10000) // 10s timeout

        channel = ch
        sshIn = ch.inputStream
        sshOut = ch.outputStream

        state = State.ESTABLISHED
        readThread.start()
    }

    @Synchronized
    fun processPacket(buffer: ByteBuffer, ipHeaderLen: Int, tcpHeaderLen: Int, payloadLen: Int) {
        val flags = Packet.getTcpFlags(buffer, ipHeaderLen)
        val seq = Packet.getTcpSeqNum(buffer, ipHeaderLen)
        val ack = Packet.getTcpAckNum(buffer, ipHeaderLen)

        // Simple state processing
        if (flags and Packet.TCP_FLAG_RST != 0) {
            close()
            return
        }

        if (state == State.ESTABLISHED) {
            if (payloadLen > 0) {
                // DATA
                // We should check SEQ order, but for now we assume browsers behave nicely.
                // Update Peer Seq
                peerSeq = seq + payloadLen

                // Read data
                val data = ByteArray(payloadLen)
                buffer.position(ipHeaderLen + tcpHeaderLen)
                buffer.get(data)

                // Write to SSH
                try {
                    // Note: This write is blocking. Ideally, this should be offloaded to a writer thread
                    // to prevent blocking the VPN loop. However, for this minimal implementation, we accept it.
                    sshOut?.write(data)
                    sshOut?.flush()
                    // ACK the data
                    sendAck()
                } catch (e: Exception) {
                    close()
                }
            } else if (flags and Packet.TCP_FLAG_FIN != 0) {
                // FIN
                peerSeq = seq + 1
                sendAck() // ACK the FIN
                // Send FIN to local if needed, or close stream
                state = State.CLOSE_WAIT
                close() // For this simple version, we just close.
            } else if (flags and Packet.TCP_FLAG_ACK != 0) {
                // Just an ACK. Update window?
            }
        }
    }

    private fun readLoop() {
        val buf = ByteArray(16384)
        try {
            while (isRunning.get() && state != State.CLOSED) {
                val len = sshIn?.read(buf) ?: -1
                if (len == -1) {
                    // EOF from remote
                    break
                }
                if (len > 0) {
                    // Send PSH+ACK
                    synchronized(this) {
                        sendData(buf, len)
                    }
                }
            }
        } catch (e: Exception) {
            // logger("SSH Read Error: ${e.message}")
        } finally {
            // Remote closed
            if (state == State.ESTABLISHED) {
                 synchronized(this) {
                     sendFin()
                 }
            }
            close()
        }
    }

    // Packet Construction Helpers

    private fun sendSynAck() {
        val buffer = ByteBuffer.allocate(60) // Min 40, but safety
        buildIpHeader(buffer, 44) // 20 IP + 24 TCP (Option MSS)

        // TCP
        buffer.putShort(20, destPort.toShort()) // Src Port (Server) -> Our Dest Port is local Src Port
        buffer.putShort(22, sourcePort.toShort()) // Dst Port (Client)
        buffer.putInt(24, mySeq.toInt())
        buffer.putInt(28, myAck.toInt()) // ACK the SYN

        // Header Len (6 words = 24 bytes) + Flags (SYN+ACK)
        // Data Offset: 6 << 4 = 0x60. Flags: SYN(2) | ACK(16) = 18 (0x12)
        buffer.putShort(32, 0x6012.toShort())
        buffer.putShort(34, WINDOW_SIZE.toShort())
        buffer.putShort(36, 0) // Checksum
        buffer.putShort(38, 0) // Urgent

        // MSS Option (Kind=2, Len=4, Val=1360) - Safe MTU
        buffer.put(40, 2.toByte())
        buffer.put(41, 4.toByte())
        buffer.putShort(42, 1360.toShort())

        Packet.calculateTCPChecksum(buffer, 20, 44, destIp, sourceIp) // Note: Swapped src/dst for response
        tun2Socks.writePacket(buffer, 44)

        mySeq++
    }

    private fun sendAck() {
        val buffer = ByteBuffer.allocate(40)
        buildIpHeader(buffer, 40)

        buffer.putShort(20, destPort.toShort())
        buffer.putShort(22, sourcePort.toShort())
        buffer.putInt(24, mySeq.toInt())
        buffer.putInt(28, myAck.toInt()) // Current ACK

        // Header Len (5 words = 20) + Flags (ACK)
        // 0x5010
        buffer.putShort(32, 0x5010.toShort())
        buffer.putShort(34, WINDOW_SIZE.toShort())
        buffer.putShort(36, 0)
        buffer.putShort(38, 0)

        Packet.calculateTCPChecksum(buffer, 20, 40, destIp, sourceIp)
        tun2Socks.writePacket(buffer, 40)
    }

    private fun sendData(data: ByteArray, len: Int) {
        val totalLen = 40 + len
        val buffer = ByteBuffer.allocate(totalLen)
        buildIpHeader(buffer, totalLen)

        buffer.putShort(20, destPort.toShort())
        buffer.putShort(22, sourcePort.toShort())
        buffer.putInt(24, mySeq.toInt())
        buffer.putInt(28, myAck.toInt())

        // Header Len 20 + Flags (PSH+ACK = 24 / 0x18)
        buffer.putShort(32, 0x5018.toShort())
        buffer.putShort(34, WINDOW_SIZE.toShort())
        buffer.putShort(36, 0)
        buffer.putShort(38, 0)

        // Payload
        buffer.position(40)
        buffer.put(data, 0, len)

        Packet.calculateTCPChecksum(buffer, 20, totalLen, destIp, sourceIp)
        tun2Socks.writePacket(buffer, totalLen)

        mySeq += len
    }

    private fun sendFin() {
        val buffer = ByteBuffer.allocate(40)
        buildIpHeader(buffer, 40)

        buffer.putShort(20, destPort.toShort())
        buffer.putShort(22, sourcePort.toShort())
        buffer.putInt(24, mySeq.toInt())
        buffer.putInt(28, myAck.toInt())

        // FIN + ACK
        buffer.putShort(32, 0x5011.toShort())
        buffer.putShort(34, WINDOW_SIZE.toShort())

        Packet.calculateTCPChecksum(buffer, 20, 40, destIp, sourceIp)
        tun2Socks.writePacket(buffer, 40)
    }

    private fun sendRst() {
        val buffer = ByteBuffer.allocate(40)
        buildIpHeader(buffer, 40)

        buffer.putShort(20, destPort.toShort())
        buffer.putShort(22, sourcePort.toShort())
        buffer.putInt(24, mySeq.toInt())
        buffer.putInt(28, myAck.toInt()) // ACK invalid seq? usually 0 if RST

        // RST + ACK
        buffer.putShort(32, 0x5014.toShort())
        buffer.putShort(34, 0.toShort())

        Packet.calculateTCPChecksum(buffer, 20, 40, destIp, sourceIp)
        tun2Socks.writePacket(buffer, 40)
    }

    private fun buildIpHeader(buffer: ByteBuffer, totalLen: Int) {
        // IPv4, IHL 5
        buffer.put(0, 0x45.toByte())
        buffer.put(1, 0.toByte()) // TOS
        buffer.putShort(2, totalLen.toShort())
        buffer.putShort(4, 0.toShort()) // ID
        buffer.putShort(6, 0x4000.toShort()) // Flags: DF
        buffer.put(8, 64.toByte()) // TTL
        buffer.put(9, Packet.PROTOCOL_TCP.toByte())
        buffer.putShort(10, 0.toShort()) // Checksum calc later

        buffer.putInt(12, destIp) // Src IP (is Dst IP of flow)
        buffer.putInt(16, sourceIp) // Dst IP (is Src IP of flow)

        Packet.updateIPChecksum(buffer, 0, 20)
    }

    fun close() {
        if (isRunning.getAndSet(false)) {
            state = State.CLOSED
            try { channel?.disconnect() } catch (e: Exception) {}
            try { sshIn?.close() } catch (e: Exception) {}
            tun2Socks.removeConnection(key)
        }
    }
}
