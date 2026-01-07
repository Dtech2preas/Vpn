package com.dtech.vpn.net

import com.jcraft.jsch.Session
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

class Tun2Socks(
    private val session: Session,
    private val vpnOutput: FileOutputStream,
    private val enableUdpGw: Boolean,
    private val udpGwPort: Int,
    private val dnsServer: String,
    private val logger: (String) -> Unit
) {

    private val connections = ConcurrentHashMap<String, TcpConn>()
    private val dnsForwarder = DnsForwarder(this, session, dnsServer, logger)
    private val udpGwClient: UdpGwClient?
    private val isDnsReady = AtomicBoolean(false)

    // Packet counters for stats
    private var rxPackets = 0L
    private var txPackets = 0L

    companion object {
        private const val MAX_CONCURRENT_TCP = 4
    }

    init {
        if (enableUdpGw) {
            udpGwClient = UdpGwClient(this, session, udpGwPort, dnsServer, logger)
            udpGwClient.start()
            // If UDPGW is enabled, we assume it works for DNS, so we set DNS Ready immediately
            // or we could implement a self-test in UdpGwClient too.
            // For now, let's mark ready.
            setDnsReady(true)
        } else {
            udpGwClient = null
            // Start the legacy DNS loop immediately if UDPGW is not used
            dnsForwarder.start()
        }
    }

    fun setDnsReady(ready: Boolean) {
        if (isDnsReady.get() != ready) {
            isDnsReady.set(ready)
            logger("Traffic Control: DNS is now ${if (ready) "READY" else "NOT READY"}")
        }
    }

    fun processPacket(buffer: ByteBuffer, length: Int) {
        rxPackets++

        // 1. Basic Parse
        if (Packet.getIPVersion(buffer) != 4) return // IPv4 Only

        val ipHeaderLen = Packet.getIPHeaderLength(buffer)
        val totalLen = Packet.getIPTotalLength(buffer)
        val protocol = Packet.getIPProtocol(buffer)
        val srcIp = Packet.getIPSrcAddress(buffer)
        val dstIp = Packet.getIPDstAddress(buffer)

        if (protocol == Packet.PROTOCOL_UDP) {
            val dstPort = Packet.getUdpDstPort(buffer, ipHeaderLen)

            if (enableUdpGw && udpGwClient != null) {
                // Route ALL UDP through UDPGW
                udpGwClient.processPacket(buffer, length)
            } else {
                // Legacy Mode: Only handle DNS
                if (dstPort == 53) {
                    // DNS: Pass to forwarder regardless of ready state (it handles its own connection)
                    // But DnsForwarder checks if channel is open.
                    val payloadLen = totalLen - ipHeaderLen - 8
                    dnsForwarder.processPacket(buffer, ipHeaderLen, 8, payloadLen)
                }
            }
        } else if (protocol == Packet.PROTOCOL_TCP) {
            val srcPort = Packet.getTcpSrcPort(buffer, ipHeaderLen)
            val dstPort = Packet.getTcpDstPort(buffer, ipHeaderLen)
            val tcpHeaderLen = Packet.getTcpHeaderLength(buffer, ipHeaderLen)
            val payloadLen = totalLen - ipHeaderLen - tcpHeaderLen

            val flags = Packet.getTcpFlags(buffer, ipHeaderLen)
            val isSyn = (flags and Packet.TCP_FLAG_SYN) != 0

            val key = "$srcIp:$srcPort->$dstIp:$dstPort"
            var conn = connections[key]

            if (conn == null) {
                if (isSyn) {
                    // TRAFFIC GATING: Check DNS Ready
                    if (!isDnsReady.get()) {
                         // Drop silently or log verbose?
                         // logger("Dropped SYN (DNS not ready): $key")
                         return
                    }

                    // TRAFFIC GATING: Check Concurrent Limit
                    if (connections.size >= MAX_CONCURRENT_TCP) {
                        logger("Dropped SYN (Max connections reached): $key")
                        return
                    }

                    logger("New Connection: $key")
                    val srcIpInt = Packet.getIPSrcInt(buffer)
                    val dstIpInt = Packet.getIPDstInt(buffer)
                    val seq = Packet.getTcpSeqNum(buffer, ipHeaderLen)

                    conn = TcpConn(this, key, session, srcIpInt, srcPort, dstIpInt, dstPort, seq, logger)
                    connections[key] = conn
                } else {
                    // Packet for unknown flow that isn't SYN. Ignore.
                }
            } else {
                conn.processPacket(buffer, ipHeaderLen, tcpHeaderLen, payloadLen)
            }
        }
    }

    fun writePacket(buffer: ByteBuffer, length: Int) {
        synchronized(vpnOutput) {
            try {
                vpnOutput.write(buffer.array(), 0, length)
                txPackets++
            } catch (e: Exception) {
                logger("Write Error: ${e.message}")
            }
        }
    }

    fun removeConnection(key: String) {
        connections.remove(key)
        logger("Closed: $key. Active: ${connections.size}")
    }

    fun close() {
        dnsForwarder.stop()
        udpGwClient?.stop()
        // Close all TCP connections
        connections.values.forEach { it.close() }
        connections.clear()
    }
}
