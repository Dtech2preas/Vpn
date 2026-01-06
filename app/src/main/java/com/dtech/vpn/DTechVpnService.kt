package com.dtech.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
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
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD = "password"

        const val BROADCAST_LOG = "com.dtech.vpn.LOG"
        const val BROADCAST_STATUS = "com.dtech.vpn.STATUS"

        const val STATUS_DISCONNECTED = 0
        const val STATUS_CONNECTING = 1
        const val STATUS_CONNECTED = 2
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
            val user = intent.getStringExtra(EXTRA_USERNAME) ?: ""
            val pass = intent.getStringExtra(EXTRA_PASSWORD) ?: ""

            if (!isRunning.get()) {
                startVpn(host, port, sni, user, pass)
            }
            return START_STICKY
        }

        return START_NOT_STICKY
    }

    private fun startVpn(host: String, port: Int, sni: String, user: String, pass: String) {
        log("Starting SSH/TLS connection to $host:$port via SNI: $sni")
        updateStatus(STATUS_CONNECTING)
        isRunning.set(true)

        vpnThread = Thread {
            try {
                runVpnLoop(host, port, sni, user, pass)
            } catch (e: Exception) {
                log("Error in VPN loop: ${e.message}")
                e.printStackTrace()
            } finally {
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

    private fun runVpnLoop(host: String, port: Int, sni: String, user: String, pass: String) {
        var tunnel: SshTlsTunnel? = null
        try {
            log("Connecting to $host...")
            tunnel = SshTlsTunnel(host, port, sni, user, pass) { message ->
                log(message)
            }
            tunnel.connect()
            log("SSH Connection established and authenticated!")
        } catch (e: Exception) {
            log("Failed to connect: ${e.message}")
            if (e.message?.contains("closed by foreign host") == true) {
                log("HINT: Server closed connection immediately. It might be expecting Websockets (use a Payload?) or the Server IP is incorrect (Cloudflare proxy?).")
            }
            return
        }

        val builder = Builder()
        builder.setSession("D-Tech VPN")
        builder.addAddress("10.0.0.2", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer("8.8.8.8")

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        try {
            vpnInterface = builder.establish()
            log("TUN interface established")
            updateStatus(STATUS_CONNECTED)
        } catch (e: Exception) {
            log("Failed to establish TUN: ${e.message}")
            return
        }

        val vpnFd = vpnInterface?.fileDescriptor
        if (vpnFd == null) {
            return
        }

        val vpnInput = FileInputStream(vpnFd)
        val bufferSize = 32767

        try {
            val buf = ByteArray(bufferSize)

            while (isRunning.get() && tunnel.isConnected()) {
                val read = vpnInput.read(buf)
                if (read > 0) {
                    // Traffic sinking
                }
            }
        } catch (e: IOException) {
            log("TUN reader error: ${e.message}")
        } finally {
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
