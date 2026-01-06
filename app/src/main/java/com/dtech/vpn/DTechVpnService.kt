package com.dtech.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.dtech.vpn.net.Tun2Socks
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

class DTechVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.dtech.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.dtech.vpn.DISCONNECT"

        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_SNI = "sni"
        const val EXTRA_ENABLE_CAMOUFLAGE = "enable_camouflage"
        const val EXTRA_PAYLOAD = "payload"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD = "password"
        const val EXTRA_FORCE_TLS_12 = "force_tls12"

        const val BROADCAST_LOG = "com.dtech.vpn.LOG"
        const val BROADCAST_STATUS = "com.dtech.vpn.STATUS"

        // Status constants
        const val STATUS_DISCONNECTED = 0
        const val STATUS_CONNECTING = 1
        const val STATUS_CONNECTED = 2

        private const val MAX_RETRIES = 3
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    private val isRunning = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action

        if (action == ACTION_DISCONNECT) {
            stopVpn()
            return START_NOT_STICKY
        }

        if (action == ACTION_CONNECT) {
            val host = intent.getStringExtra(EXTRA_HOST) ?: ""
            val port = intent.getIntExtra(EXTRA_PORT, 22)
            val sni = intent.getStringExtra(EXTRA_SNI) ?: ""
            val enableCamouflage = intent.getBooleanExtra(EXTRA_ENABLE_CAMOUFLAGE, false)
            val payload = intent.getStringExtra(EXTRA_PAYLOAD) ?: ""
            val user = intent.getStringExtra(EXTRA_USERNAME) ?: ""
            val pass = intent.getStringExtra(EXTRA_PASSWORD) ?: ""
            val forceTls12 = intent.getBooleanExtra(EXTRA_FORCE_TLS_12, false)

            if (!isRunning.get()) {
                startVpn(host, port, sni, payload, enableCamouflage, user, pass, forceTls12)
            }
            return START_STICKY
        }

        return START_NOT_STICKY
    }

    private fun startVpn(host: String, port: Int, sni: String, payload: String, enableCamouflage: Boolean, user: String, pass: String, forceTls12: Boolean) {
        log("Starting VPN connection to $host:$port")
        if (sni.isNotEmpty()) log("SNI: $sni")
        log("Camouflage: $enableCamouflage")
        if (enableCamouflage && payload.isNotEmpty()) log("Payload: [Hidden for brevity]")
        log("Force TLS 1.2: $forceTls12")

        updateStatus(STATUS_CONNECTING)
        isRunning.set(true)

        vpnThread = Thread {
            var attempt = 0
            var connected = false

            while (attempt < MAX_RETRIES && !connected && isRunning.get()) {
                attempt++
                if (attempt > 1) {
                    log("Retrying connection... (Attempt $attempt/$MAX_RETRIES)")
                    try {
                        Thread.sleep(2000)
                    } catch (e: InterruptedException) {
                        break
                    }
                }

                try {
                    runVpnLoop(host, port, sni, payload, enableCamouflage, user, pass, forceTls12)
                    connected = true
                } catch (e: Exception) {
                    log("Connection failed: ${e.message}")
                    e.printStackTrace()
                }
            }

            // If we exited the loop and are not running, we are done.
            if (isRunning.get()) {
                stopVpn()
            }
        }
        vpnThread?.start()
    }

    private fun stopVpn() {
        log("Stopping VPN service")
        isRunning.set(false)
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            // Ignore
        }
        vpnInterface = null
        updateStatus(STATUS_DISCONNECTED)
        stopSelf()
    }

    private fun runVpnLoop(host: String, port: Int, sni: String, payload: String, enableCamouflage: Boolean, user: String, pass: String, forceTls12: Boolean) {
        var tunnel: SshTlsTunnel? = null
        try {
            log("Initializing SSH Tunnel...")

            // Pass the logging function to the tunnel so it can report progress back to UI
            tunnel = SshTlsTunnel(host, port, sni, payload, enableCamouflage, user, pass, forceTls12) { msg -> log(msg) }

            tunnel.connect()
            log("SSH Connection established and authenticated!")
        } catch (e: Exception) {
            log("Failed to connect: ${e.message}")
            // Throw to trigger retry logic
            throw e
        }

        // 2. Configure TUN interface
        // We use a private IP address for the Android device.
        val builder = Builder()
        builder.setSession("D-Tech VPN")
        builder.addAddress("10.0.0.2", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer("8.8.8.8")
        builder.setMtu(1500)

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        try {
            vpnInterface = builder.establish()
            log("TUN interface established")
            updateStatus(STATUS_CONNECTED)
        } catch (e: Exception) {
            log("Failed to establish TUN: ${e.message}")
            tunnel?.close()
            throw e
        }

        val vpnFd = vpnInterface?.fileDescriptor
        if (vpnFd == null) {
             tunnel?.close()
             return
        }

        val vpnInput = FileInputStream(vpnFd)
        val vpnOutput = FileOutputStream(vpnFd)

        // Initialize Tun2Socks
        val tun2Socks = Tun2Socks(tunnel.getSession()!!, vpnOutput) { msg -> log(msg) }
        log("Tun2Socks Initialized")

        // 3. Forwarding Loop
        try {
            val buf = ByteArray(16384)
            val buffer = ByteBuffer.wrap(buf)

            while (isRunning.get() && tunnel.isConnected()) {
                // Read from TUN (Blocking)
                val read = vpnInput.read(buf)
                if (read > 0) {
                    buffer.position(0)
                    buffer.limit(read)
                    tun2Socks.processPacket(buffer, read)
                }
            }
        } catch (e: IOException) {
            if (isRunning.get()) {
                log("TUN reader error: ${e.message}")
            }
        } finally {
            log("VPN Loop Finished")
            try {
                tunnel.close()
            } catch (e: Exception) {}
        }
    }

    private fun log(message: String) {
        Log.d("DTechVpn", message)
        val intent = Intent(BROADCAST_LOG)
        intent.putExtra("log", message)
        sendBroadcast(intent)
    }

    private fun updateStatus(status: Int) {
        val intent = Intent(BROADCAST_STATUS)
        intent.putExtra("status", status)
        sendBroadcast(intent)
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }
}
