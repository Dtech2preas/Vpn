package com.dtech.vpn

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

class Socks5Proxy(
    private val session: Session,
    private val port: Int,
    private val logger: (String) -> Unit
) : Thread() {

    private var serverSocket: ServerSocket? = null
    private val isRunning = AtomicBoolean(false)

    override fun run() {
        try {
            serverSocket = ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"))
            isRunning.set(true)
            logger("SOCKS5 Server listening on 127.0.0.1:$port")

            while (isRunning.get()) {
                try {
                    val client = serverSocket?.accept() ?: break
                    Thread { handleClient(client) }.start()
                } catch (e: IOException) {
                    if (isRunning.get()) {
                        logger("SOCKS5 Accept Error: ${e.message}")
                    }
                }
            }
        } catch (e: Exception) {
            logger("SOCKS5 Start Error: ${e.message}")
        } finally {
            close()
        }
    }

    private fun handleClient(socket: Socket) {
        try {
            val input = DataInputStream(socket.getInputStream())
            val output = DataOutputStream(socket.getOutputStream())

            // SOCKS5 Handshake
            // Client: Ver(1) + NMethods(1) + Methods(N)
            val ver = input.read()
            if (ver != 5) {
                socket.close()
                return
            }
            val nMethods = input.read()
            val methods = ByteArray(nMethods)
            input.readFully(methods)

            // Server: Ver(1) + Method(1) (0x00 = No Auth)
            output.write(byteArrayOf(5, 0))
            output.flush()

            // Client Request: Ver(1) + Cmd(1) + Rsv(1) + Atyp(1) + DstAddr(...) + DstPort(2)
            val ver2 = input.read()
            val cmd = input.read()
            val rsv = input.read()
            val atyp = input.read()

            if (ver2 != 5 || cmd != 1) { // Only CONNECT supported
                socket.close()
                return
            }

            var host = ""
            when (atyp) {
                1 -> { // IPv4
                    val ip = ByteArray(4)
                    input.readFully(ip)
                    host = InetAddress.getByAddress(ip).hostAddress
                }
                3 -> { // Domain name
                    val len = input.read()
                    val domain = ByteArray(len)
                    input.readFully(domain)
                    host = String(domain)
                }
                4 -> { // IPv6
                    val ip = ByteArray(16)
                    input.readFully(ip)
                    host = InetAddress.getByAddress(ip).hostAddress
                }
                else -> {
                    socket.close()
                    return
                }
            }

            val portH = input.read()
            val portL = input.read()
            val targetPort = (portH shl 8) or portL

            // logger("SOCKS5 Request: $host:$targetPort")

            // Optimistically send Success Reply to avoid race condition with JSch channel thread
            // Server: Ver(1) + Rep(1) + Rsv(1) + Atyp(1) + BndAddr(...) + BndPort(2)
            // Rep 0 = Success
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()

            if (session.isConnected) {
                val channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP

                // Use reflection to set host/port as they are package-private in JSch
                val cls = channel.javaClass
                try {
                    val setHost = cls.getDeclaredMethod("setHost", String::class.java)
                    setHost.isAccessible = true
                    setHost.invoke(channel, host)

                    val setPort = cls.getDeclaredMethod("setPort", Int::class.javaPrimitiveType)
                    setPort.isAccessible = true
                    setPort.invoke(channel, targetPort)

                    val setOrgIp = cls.getDeclaredMethod("setOrgIPAddress", String::class.java)
                    setOrgIp.isAccessible = true
                    setOrgIp.invoke(channel, socket.inetAddress.hostAddress)

                    val setOrgPort = cls.getDeclaredMethod("setOrgPort", Int::class.javaPrimitiveType)
                    setOrgPort.isAccessible = true
                    setOrgPort.invoke(channel, socket.port)
                } catch (e: Exception) {
                    logger("Reflection Error: ${e.message}")
                    // Fallback or rethrow if critical
                }

                channel.setInputStream(socket.getInputStream())
                channel.setOutputStream(socket.getOutputStream())
                channel.connect(10000) // 10s timeout
                // JSch channel thread now handles the data pumping
            } else {
                socket.close()
            }

        } catch (e: Exception) {
            // logger("SOCKS5 Handler Error: ${e.message}")
            try { socket.close() } catch(ignore: Exception){}
        }
    }

    fun close() {
        isRunning.set(false)
        try {
            serverSocket?.close()
        } catch (e: Exception) {}
    }
}
