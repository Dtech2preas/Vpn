package com.dtech.vpn

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

class Socks5Proxy(
    private val session: Session,
    private val port: Int,
    private val logger: (String) -> Unit
) : Thread() {

    private val running = AtomicBoolean(true)
    private var serverSocket: ServerSocket? = null

    override fun run() {
        try {
            serverSocket = ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"))
            logger("SOCKS5 Proxy listening on 127.0.0.1:$port")

            while (running.get()) {
                try {
                    val client = serverSocket?.accept() ?: break
                    Thread { handleClient(client) }.start()
                } catch (e: Exception) {
                    if (running.get()) logger("Socks5 accept error: ${e.message}")
                }
            }
        } catch (e: Exception) {
            logger("Socks5 server error: ${e.message}")
        }
    }

    fun stopProxy() {
        running.set(false)
        try {
            serverSocket?.close()
        } catch (e: Exception) {}
    }

    private fun handleClient(socket: Socket) {
        val input = socket.getInputStream()
        val output = socket.getOutputStream()

        try {
            // SOCKS5 Handshake
            // 1. Client greets
            val ver = input.read()
            if (ver != 5) return // Not SOCKS5

            val nmethods = input.read()
            val methods = ByteArray(nmethods)
            readFull(input, methods)

            // 2. Server chooses method (0x00 No Auth)
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            // 3. Client Request
            val ver2 = input.read() // 5
            val cmd = input.read() // 1 = Connect
            val rsv = input.read() // 0
            val atyp = input.read() // 1=IPv4, 3=Domain, 4=IPv6

            var host = ""
            when (atyp) {
                1 -> { // IPv4
                    val ip = ByteArray(4)
                    readFull(input, ip)
                    host = InetAddress.getByAddress(ip).hostAddress
                }
                3 -> { // Domain
                    val len = input.read()
                    val domain = ByteArray(len)
                    readFull(input, domain)
                    host = String(domain)
                }
                4 -> { // IPv6
                    val ip = ByteArray(16)
                    readFull(input, ip)
                    host = InetAddress.getByAddress(ip).hostAddress
                }
                else -> return // Unsupported
            }

            val b1 = input.read()
            val b2 = input.read()
            val targetPort = ((b1 and 0xFF) shl 8) or (b2 and 0xFF)

            // 4. Connect via SSH
            if (cmd == 1) { // Connect
                handleConnect(socket, input, output, host, targetPort)
            } else {
                // Unsupported command
                output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0)) // Command not supported
                output.flush()
                socket.close()
            }

        } catch (e: Exception) {
            // logger("Socks5 Client Error: ${e.message}")
            try { socket.close() } catch (e2: Exception) {}
        }
    }

    private fun handleConnect(clientSocket: Socket, clientIn: InputStream, clientOut: OutputStream, host: String, port: Int) {
        var channel: ChannelDirectTCPIP? = null
        try {
            channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP

            // Reflection to invoke package-private setters
            invokePrivateSetter(channel, "setHost", String::class.java, host)
            invokePrivateSetter(channel, "setPort", Int::class.javaPrimitiveType!!, port)
            invokePrivateSetter(channel, "setOrgIPAddress", String::class.java, "127.0.0.1")
            invokePrivateSetter(channel, "setOrgPort", Int::class.javaPrimitiveType!!, clientSocket.port)

            // Connect with timeout
            channel.connect(10000)

            // Reply Success
            clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            clientOut.flush()

            // Pipe data
            val sshIn = channel.inputStream
            val sshOut = channel.outputStream

            val t1 = Thread { pipe(clientIn, sshOut) }
            val t2 = Thread { pipe(sshIn, clientOut) }
            t1.start()
            t2.start()

            t1.join()
            t2.join()

        } catch (e: Exception) {
            // logger("Socks5 Connect Failed: ${e.message}")
            try {
                 clientOut.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0)) // Host unreachable
                 clientOut.flush()
            } catch (ignore: Exception) {}
        } finally {
            channel?.disconnect()
            try { clientSocket.close() } catch (e: Exception) {}
        }
    }

    private fun invokePrivateSetter(obj: Any, name: String, type: Class<*>, value: Any) {
        var clazz: Class<*>? = obj.javaClass
         while (clazz != null) {
            try {
                val method = clazz.getDeclaredMethod(name, type)
                method.isAccessible = true
                method.invoke(obj, value)
                return
            } catch (e: NoSuchMethodException) {
                clazz = clazz.superclass
            }
        }
    }

    private fun readFull(input: InputStream, buf: ByteArray) {
        var read = 0
        while (read < buf.size) {
            val r = input.read(buf, read, buf.size - read)
            if (r == -1) throw Exception("EOF")
            read += r
        }
    }

    private fun pipe(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(8192)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read == -1) break
                output.write(buffer, 0, read)
                output.flush()
            }
        } catch (e: Exception) {
            // pipe broken
        }
    }
}
