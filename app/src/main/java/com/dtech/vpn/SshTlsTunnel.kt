package com.dtech.vpn

import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Implements the Strict Protocol Pipeline for Zero-Rated SNI Tunneling.
 *
 * Pipeline:
 * 1. Raw TCP Socket -> Server Port
 * 2. TLS Layer (with SNI Injection) -> Handshake
 * 3. [Optional] HTTP Camouflage (Payload)
 * 4. SSH Protocol (JSch)
 */
class SshTlsTunnel(
    private val host: String,
    private val port: Int,
    private val sni: String,
    private val payload: String,
    private val enableCamouflage: Boolean, // New flag: "Use Payload"
    private val user: String,
    private val pass: String,
    private val forceTls12: Boolean,
    private val logger: (String) -> Unit
) {

    private var session: Session? = null
    private var sslSocket: SSLSocket? = null
    private var isWebSocket = false
    private var wsIn: WebSocketInputStream? = null
    private var wsOut: WebSocketOutputStream? = null
    private var socksProxy: Socks5Proxy? = null

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
                if (isWebSocket && wsIn != null) {
                    return wsIn!!
                }
                return socket!!.inputStream
            }

            override fun getOutputStream(socket: Socket?): OutputStream {
                if (isWebSocket && wsOut != null) {
                    return wsOut!!
                }
                return socket!!.outputStream
            }
        })

        // 30 seconds timeout
        session?.setServerAliveInterval(15000) // Send keepalive every 15 seconds
        // Increased timeout to 60s for slow mobile networks and WS handshake
        session?.connect(60000)

        // Enable Dynamic Port Forwarding (SOCKS5 Server)
        // This listens on localhost:10808 and forwards traffic through the SSH tunnel
        // Using manual implementation as JSch setPortForwardingD is unreliable/unavailable
        socksProxy = Socks5Proxy(session!!, 10808, logger)
        socksProxy?.start()
        logger("SOCKS5 Proxy enabled on 127.0.0.1:10808")
    }

    private fun createTlsSocket(): Socket {
        logger("Creating socket to $host:$port")

        // Trust All Certs (Security Risk, but standard for these 'free internet' tools)
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        })

        val protocol = if (forceTls12) "TLSv1.2" else "TLS"
        logger("Initializing SSL Context with $protocol...")
        val sslContext = SSLContext.getInstance(protocol)
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())
        val factory = sslContext.socketFactory

        // 1. Establish plain TCP connection first
        // This ensures DNS resolution happens here and connection is established
        val plainSocket = Socket()
        try {
            plainSocket.connect(InetSocketAddress(host, port), 30000)
        } catch (e: Exception) {
             logger("TCP Connection failed: ${e.message}")
             throw e
        }

        // 2. Determine the Host to use for SNI and Verification
        // If user provided SNI, use it. Otherwise use the connection host.
        // In this "Strict SNI" model, SNI should be mandatory, but we fallback gracefully if empty.
        val peerHost = if (sni.isNotEmpty()) sni else host

        // 3. Layer the SSL Socket
        // autoClose=true: Closing the SSL socket will close the underlying plain socket
        val socket = factory.createSocket(plainSocket, peerHost, port, true) as SSLSocket

        // 4. Double check SNI setting via SSLParameters
        // The peerHost arg above usually sets the SNI automatically, but we can enforce it.
        if (sni.isNotEmpty()) {
             if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                val params = socket.sslParameters
                // Only set if not already set (though overriding is fine)
                 val currentSni = params.serverNames
                 if (currentSni == null || currentSni.isEmpty()) {
                     params.serverNames = listOf(javax.net.ssl.SNIHostName(sni))
                     socket.sslParameters = params
                 }
            }
        }

        if (forceTls12) {
             socket.enabledProtocols = arrayOf("TLSv1.2")
        }

        logger("Starting TLS Handshake with SNI: $peerHost")
        try {
            socket.startHandshake()
            logger("TLS Handshake successful!")
        } catch (e: Exception) {
            logger("TLS Handshake failed: ${e.message}")
            throw e
        }
        sslSocket = socket

        // 5. Send Payload (Optional Camouflage)
        // If disabled, we skip this entirely and go straight to SSH
        if (enableCamouflage && payload.isNotEmpty()) {
             logger("Sending Payload...")
             val out = socket.outputStream
             val processedPayload = payload.replace("[crlf]", "\r\n")
                                           .replace("[lf]", "\n")
                                           .replace("[cr]", "\r")
                                           .replace("[host]", host)
                                           .replace("[port]", port.toString())
                                           .replace("[sni]", sni)


             // Ensure it ends with a double CRLF if it looks like an HTTP request
             val finalPayload = if (!processedPayload.endsWith("\r\n\r\n")) {
                 "$processedPayload\r\n\r\n"
             } else {
                 processedPayload
             }

             out.write(finalPayload.toByteArray())
             out.flush()
             logger("Payload sent!")

             // Note: If the payload is a WebSocket Upgrade, the server will send an HTTP 101 response.
             // JSch expects the SSH version string (SSH-2.0-...) immediately.
             // We need to consume the HTTP headers until the empty line before handing off to JSch.
             // However, JSch is strict. If it sees "HTTP/1.1 101...", it might fail or it might tolerate it if it finds "SSH-" later.
             // Standard practice in these tools is to strip the HTTP response.
             if (checkAndConsumeHttpResponse(socket.inputStream)) {
                 logger("Switching to WebSocket Framing Mode.")
                 isWebSocket = true

                 // Create Output Stream first so it's available for reference,
                 // although the input stream uses it in a callback, which will be called later.
                 val wsOutLocal = WebSocketOutputStream(socket.outputStream, logger)
                 wsOut = wsOutLocal

                 // Pass callback to switch output mode if raw banner detected
                 // The callback now receives a boolean: true = Raw, false = WebSocket
                 wsIn = WebSocketInputStream(socket.inputStream, logger) { isRaw ->
                     // Callback: Protocol Detected
                     wsOutLocal.determineMode(isRaw)
                     if (isRaw) {
                        try { Thread.sleep(150) } catch (e: Exception) {}
                     }
                 }
             }
        } else {
            logger("Payload skipped (Direct SSL/TLS Mode).")
        }

        return socket
    }

    private fun checkAndConsumeHttpResponse(input: InputStream): Boolean {
        // Simple state machine to read until \r\n\r\n
        // This is a naive implementation but sufficient for this context.
        logger("Reading HTTP Response...")
        val buffer = StringBuilder()

        // We read byte by byte to avoid over-reading into the SSH stream
        var b: Int
        var count = 0
        while (count < 4096) { // Safety limit 4kb header
            b = input.read()
            if (b == -1) break
            buffer.append(b.toChar())

            // Check for \r\n\r\n (13, 10, 13, 10)
            // A simple way is to check the end of the StringBuilder
            if (buffer.endsWith("\r\n\r\n")) {
                logger("HTTP Response Header received (Length: ${buffer.length})")

                val header = buffer.toString()
                // Status line is the first line: HTTP/1.1 101 Switching Protocols
                val statusLine = header.lines().firstOrNull()
                if (statusLine != null && statusLine.contains(" 101 ")) {
                    logger("Server accepted WebSocket Upgrade (HTTP 101).")
                    return true
                }
                return false
            }
            count++
        }
        logger("Warning: HTTP Response header too large or not found. Passing stream to JSch anyway.")
        return false
    }

    fun isConnected(): Boolean {
        return session?.isConnected == true
    }

    fun getSession(): Session? {
        return session
    }

    fun close() {
        try {
            socksProxy?.close()
        } catch (e: Exception) {}
        try {
            session?.disconnect()
        } catch (e: Exception) {}
        try {
            sslSocket?.close()
        } catch (e: Exception) {}
    }
}
