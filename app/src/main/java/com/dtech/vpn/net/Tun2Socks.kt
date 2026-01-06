package com.dtech.vpn.net

import com.jcraft.jsch.Session
import java.io.OutputStream
import java.util.concurrent.ConcurrentHashMap

class Tun2Socks(
    val session: Session,
    val tunWriter: OutputStream
) {
    private val tcpConns = ConcurrentHashMap<String, TcpConn>()
    private val dnsForwarder = DnsForwarder(session, tunWriter)

    fun processPacket(data: ByteArray, length: Int) {
        try {
            val packet = Packet(data, length)

            // Only support IPv4
            if (packet.version != 4) return

            if (packet.protocol == 6) { // TCP
                handleTcp(packet)
            } else if (packet.protocol == 17) { // UDP
                // Only handle DNS (Port 53)
                if (packet.destinationPort == 53) {
                    dnsForwarder.handleDnsRequest(packet)
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun handleTcp(packet: Packet) {
        val key = "${packet.sourceAddress}:${packet.sourcePort}->${packet.destinationAddress}:${packet.destinationPort}"

        var conn = tcpConns[key]

        if (packet.isSyn && !packet.isAck) {
            // New Connection
            if (conn != null) {
                // Reset existing?
                conn.close()
            }
            conn = TcpConn(
                session,
                packet.sourceAddress,
                packet.sourcePort,
                packet.destinationAddress,
                packet.destinationPort,
                packet.seqNum,
                tunWriter
            ) { c ->
                tcpConns.remove(key)
            }
            tcpConns[key] = conn
            conn.start()
            return
        }

        if (conn != null) {
            if (packet.isFin || packet.isRst) {
                conn.close()
                tcpConns.remove(key)
                return
            }

            if (packet.payloadSize > 0) {
                conn.sendData(packet.data, packet.payloadOffset, packet.payloadSize, packet.seqNum)
            }
        } else {
            // Received packet for unknown connection.
            // If it is not SYN, send RST?
            // For now, ignore.
        }
    }
}
