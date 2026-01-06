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
    private val pass: String
) {

    private var session: Session? = null
    private var sslSocket: SSLSocket? = null

    fun connect() {
        val jsch = JSch()
        session = jsch.getSession(user, host, port)
        session?.setPassword(pass)

        // Skip host key check for simplicity in this user tool context
        val config = java.util.Properties()
        config["StrictHostKeyChecking"] = "no"
        session?.setConfig(config)

        // Set custom socket factory to use SSL/TLS
        session?.setSocketFactory(object : SocketFactory {
            override fun createSocket(host: String?, port: Int): Socket {
                // Ignore the host/port passed by JSch (which are the SSH server details)
                // We use the ones we already know, but technically they match.
                return createTlsSocket()
            }

            override fun getInputStream(socket: Socket?): InputStream {
                return socket!!.inputStream
            }

            override fun getOutputStream(socket: Socket?): OutputStream {
                return socket!!.outputStream
            }
        })

        // 30 seconds timeout
        session?.connect(30000)
    }

    private fun createTlsSocket(): Socket {
        // Trust All Certs (Security Risk, but standard for these 'free internet' tools)
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        })

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())
        val factory = sslContext.socketFactory

        val socket = factory.createSocket(host, port) as SSLSocket

        // Set SNI
        if (sni.isNotEmpty()) {
            val params = socket.sslParameters
            // Reflection or API check not strictly needed since minSdk=24
            // But we need to use SNIHostName
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                params.serverNames = listOf(javax.net.ssl.SNIHostName(sni))
                socket.sslParameters = params
            }
        }

        socket.startHandshake()
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

    // Future extension: Port forwarding methods
    // fun setPortForwardingL(localPort: Int, remoteHost: String, remotePort: Int) ...
}
