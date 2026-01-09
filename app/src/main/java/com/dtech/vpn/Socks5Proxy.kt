package com.dtech.vpn

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

class Socks5Proxy(
    private val session: Session,
    private val port: Int,
    private val logger: (String) -> Unit
) {
    private var serverSocket: ServerSocket? = null
    private val isRunning = AtomicBoolean(false)
    private var acceptThread: Thread? = null

    fun start() {
        if (isRunning.get()) return
        isRunning.set(true)
        try {
            serverSocket = ServerSocket(port, 0, InetAddress.getByName("127.0.0.1"))
            logger("SOCKS5 Proxy started on 127.0.0.1:$port")
            acceptThread = Thread {
                while (isRunning.get()) {
                    try {
                        val client = serverSocket?.accept() ?: break
                        Thread { handleClient(client) }.start()
                    } catch (e: Exception) {
                        if (isRunning.get()) {
                            logger("SOCKS5 Accept error: ${e.message}")
                        }
                    }
                }
            }
            acceptThread?.start()
        } catch (e: Exception) {
            logger("Failed to start SOCKS5 Proxy: ${e.message}")
            isRunning.set(false)
        }
    }

    fun stop() {
        isRunning.set(false)
        try {
            serverSocket?.close()
        } catch (e: Exception) {}
        try {
            acceptThread?.interrupt()
        } catch (e: Exception) {}
        logger("SOCKS5 Proxy stopped")
    }

    private fun handleClient(socket: Socket) {
        try {
            val `in` = DataInputStream(socket.getInputStream())
            val out = DataOutputStream(socket.getOutputStream())

            // SOCKS5 Handshake
            // Client sends: VER(1) NMETHODS(1) METHODS(1-255)
            val ver = `in`.read()
            if (ver != 5) {
                socket.close()
                return
            }
            val nMethods = `in`.read()
            val methods = ByteArray(nMethods)
            `in`.readFully(methods)

            // We only support NO AUTH (0x00)
            // Server sends: VER(1) METHOD(1)
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            // Request
            // Client sends: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR DST.PORT
            val reqVer = `in`.read()
            val cmd = `in`.read()
            val rsv = `in`.read()
            val atyp = `in`.read()

            if (reqVer != 5 || cmd != 1) { // 1 = CONNECT
                socket.close()
                return
            }

            var host = ""
            when (atyp) {
                1 -> { // IPv4
                    val ip = ByteArray(4)
                    `in`.readFully(ip)
                    host = InetAddress.getByAddress(ip).hostAddress
                }
                3 -> { // Domain name
                    val len = `in`.read()
                    val domain = ByteArray(len)
                    `in`.readFully(domain)
                    host = String(domain)
                }
                4 -> { // IPv6
                    val ip = ByteArray(16)
                    `in`.readFully(ip)
                    host = InetAddress.getByAddress(ip).hostAddress
                }
                else -> {
                    socket.close()
                    return
                }
            }

            val portH = `in`.read()
            val portL = `in`.read()
            val targetPort = (portH shl 8) or portL

            logger("SOCKS5 Request: $host:$targetPort")

            try {
                val channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                channel.setHost(host)
                channel.setPort(targetPort)

                channel.setInputStream(socket.getInputStream())
                channel.setOutputStream(socket.getOutputStream())

                channel.connect(10000) // 10s timeout

                // Reply Success
                val reply = byteArrayOf(
                    0x05, 0x00, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00
                )
                out.write(reply)
                out.flush()

            } catch (e: Exception) {
                logger("SOCKS5 Connect Failed: ${e.message}")
                 val reply = byteArrayOf(
                    0x05, 0x01, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00
                )
                try {
                    out.write(reply)
                    out.flush()
                } catch (ex: Exception) {}
                socket.close()
            }

        } catch (e: Exception) {
            try { socket.close() } catch (ex: Exception) {}
        }
    }
}
