package com.dtech.vpn.net

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

class DnsForwarder(
    val session: Session,
    val tunWriter: OutputStream
) {
    // We will use 8.8.8.8:53 over TCP
    private val dnsServer = "8.8.8.8"
    private val dnsPort = 53

    fun handleDnsRequest(packet: Packet) {
        val payload = packet.data.sliceArray(packet.payloadOffset until (packet.payloadOffset + packet.payloadSize))

        Thread {
            try {
                // Open Channel to 8.8.8.8:53
                val channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                channel.setHost(dnsServer)
                channel.setPort(dnsPort)
                channel.connect(5000)

                val out = channel.outputStream
                val inp = channel.inputStream

                // DNS over TCP requires a 2-byte length prefix
                val lenBuf = ByteBuffer.allocate(2)
                lenBuf.putShort(payload.size.toShort())
                out.write(lenBuf.array())
                out.write(payload)
                out.flush()

                // Read response
                val lenBytes = ByteArray(2)
                if (inp.read(lenBytes) == 2) {
                    val respLen = ByteBuffer.wrap(lenBytes).short.toInt() and 0xFFFF
                    val respBuf = ByteArray(respLen)
                    var totalRead = 0
                    while (totalRead < respLen) {
                        val read = inp.read(respBuf, totalRead, respLen - totalRead)
                        if (read == -1) break
                        totalRead += read
                    }

                    if (totalRead == respLen) {
                        sendDnsResponse(packet, respBuf)
                    }
                }

                channel.disconnect()
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }.start()
    }

    private fun sendDnsResponse(request: Packet, responsePayload: ByteArray) {
        // Construct UDP packet
        val totalLen = 20 + 8 + responsePayload.size
        val buffer = ByteBuffer.allocate(totalLen)

        // IP Header
        buffer.put(0x45.toByte())
        buffer.put(0x00.toByte())
        buffer.putShort(totalLen.toShort())
        buffer.putShort(0.toShort())
        buffer.putShort(0x0000.toShort()) // No frag
        buffer.put(64.toByte())
        buffer.put(17.toByte()) // UDP
        buffer.putShort(0.toShort()) // Checksum

        // Src IP (DNS Server) -> Dst IP (Android)
        buffer.put(parseIp(request.destinationAddress)) // Original Dest is now Source
        buffer.put(parseIp(request.sourceAddress)) // Original Source is now Dest

        // Calc IP Checksum
        val ipChecksum = calculateChecksum(buffer.array(), 0, 20)
        buffer.putShort(10, ipChecksum.toShort())

        // UDP Header (8 bytes)
        buffer.putShort(request.destinationPort.toShort()) // Source Port (53)
        buffer.putShort(request.sourcePort.toShort()) // Dest Port
        buffer.putShort((8 + responsePayload.size).toShort()) // Length
        buffer.putShort(0.toShort()) // Checksum (0 = valid in UDP)

        // Payload
        buffer.put(responsePayload)

        synchronized(tunWriter) {
            try {
                tunWriter.write(buffer.array())
            } catch (e: Exception) {}
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
}
