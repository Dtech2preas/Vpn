package com.dtech.vpn

import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class SshTlsTunnel(
    private val host: String,
    private val port: Int,
    private val sni: String,
    private val user: String,
    private val pass: String,
    private val logCallback: (String) -> Unit
) {

    private var session: Session? = null
    private var sslSocket: SSLSocket? = null

    init {
        // Setup JSch Logging
        JSch.setLogger(object : com.jcraft.jsch.Logger {
            override fun isEnabled(level: Int): Boolean {
                return true
            }

            override fun log(level: Int, message: String) {
                // Map JSch levels to meaningful strings if needed, or just log raw
                // Level constants: DEBUG=0, INFO=1, WARN=2, ERROR=3, FATAL=4
                val prefix = when(level) {
                    com.jcraft.jsch.Logger.DEBUG -> "DEBUG"
                    com.jcraft.jsch.Logger.INFO -> "INFO"
                    com.jcraft.jsch.Logger.WARN -> "WARN"
                    com.jcraft.jsch.Logger.ERROR -> "ERROR"
                    com.jcraft.jsch.Logger.FATAL -> "FATAL"
                    else -> "LOG"
                }
                logCallback("JSch [$prefix]: $message")
            }
        })
    }

    fun connect() {
        val jsch = JSch()
        session = jsch.getSession(user, host, port)
        session?.setPassword(pass)

        val config = java.util.Properties()
        config["StrictHostKeyChecking"] = "no"
        // Add more algorithms support in case server is modern and JSch is old
        // config["server_host_key"] = "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"
        session?.setConfig(config)

        session?.setSocketFactory(object : SocketFactory {
            override fun createSocket(host: String?, port: Int): Socket {
                logCallback("Creating SSL/TLS Socket to $host:$port via SNI: $sni")
                return createTlsSocket()
            }

            override fun getInputStream(socket: Socket?): InputStream {
                return socket!!.inputStream
            }

            override fun getOutputStream(socket: Socket?): OutputStream {
                return socket!!.outputStream
            }
        })

        logCallback("JSch: Connecting session...")
        session?.connect(30000)
    }

    private fun createTlsSocket(): Socket {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        })

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())
        val factory = sslContext.socketFactory

        val socket = factory.createSocket(host, port) as SSLSocket

        if (sni.isNotEmpty()) {
            val params = socket.sslParameters
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                params.serverNames = listOf(javax.net.ssl.SNIHostName(sni))
                socket.sslParameters = params
            }
        }

        logCallback("Starting SSL Handshake...")
        socket.startHandshake()
        logCallback("SSL Handshake completed. Cipher: ${socket.session.cipherSuite}")

        sslSocket = socket
        return socket
    }

    fun isConnected(): Boolean {
        return session?.isConnected == true
    }

    fun close() {
        try {
            session?.disconnect()
        } catch (e: Exception) {}
        try {
            sslSocket?.close()
        } catch (e: Exception) {}
    }
}
