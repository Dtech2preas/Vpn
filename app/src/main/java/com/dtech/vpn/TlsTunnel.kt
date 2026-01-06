package com.dtech.vpn

import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class TlsTunnel(
    private val host: String,
    private val port: Int,
    private val token: String
) {

    private var socket: SSLSocket? = null
    var inputStream: InputStream? = null
    var outputStream: OutputStream? = null

    // Handshake constant
    private val HANDSHAKE_HEADER = "DTECH-VPN/1.0"

    fun connect() {
        // Create a trust manager that does not validate certificate chains
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        })

        // Install the all-trusting trust manager
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())

        // Create socket
        val factory = sslContext.socketFactory
        val tmpSocket = factory.createSocket(host, port) as SSLSocket
        tmpSocket.startHandshake()

        socket = tmpSocket
        inputStream = tmpSocket.inputStream
        outputStream = tmpSocket.outputStream

        performHandshake()
    }

    private fun performHandshake() {
        val out = outputStream ?: throw IllegalStateException("Socket not connected")
        val writer = out.writer(Charsets.UTF_8)

        // Protocol:
        // DTECH-VPN/1.0
        // TOKEN: <token>
        // PLATFORM: android
        // <newline>

        writer.write("$HANDSHAKE_HEADER\n")
        writer.write("TOKEN: $token\n")
        writer.write("PLATFORM: android\n")
        writer.write("\n")
        writer.flush()

        // In a real scenario, we might wait for an OK, but for this simple protocol
        // we assume if the socket stays open, we are good to go.
    }

    fun close() {
        try {
            socket?.close()
        } catch (e: Exception) {
            // Ignore
        }
    }

    fun getUnderlyingSocket(): Socket? {
        return socket
    }
}
