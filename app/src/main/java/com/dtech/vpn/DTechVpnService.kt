package com.dtech.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import hev.sockstun.TProxyService
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

class DTechVpnService : VpnService() {

    companion object {
        const val NOTIFICATION_CHANNEL_ID = "vpn_channel"
        const val NOTIFICATION_ID = 1

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
        const val EXTRA_UDPGW_ENABLED = "udpgw_enabled"
        const val EXTRA_UDPGW_PORT = "udpgw_port"
        const val EXTRA_DNS_SERVER = "dns_server"

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
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action

        if (action == ACTION_DISCONNECT) {
            stopVpn()
            return START_NOT_STICKY
        }

        if (action == ACTION_CONNECT) {
            startForegroundService()
            acquireWakeLock()

            val host = intent.getStringExtra(EXTRA_HOST) ?: ""
            val port = intent.getIntExtra(EXTRA_PORT, 22)
            val sni = intent.getStringExtra(EXTRA_SNI) ?: ""
            val enableCamouflage = intent.getBooleanExtra(EXTRA_ENABLE_CAMOUFLAGE, false)
            val payload = intent.getStringExtra(EXTRA_PAYLOAD) ?: ""
            val user = intent.getStringExtra(EXTRA_USERNAME) ?: ""
            val pass = intent.getStringExtra(EXTRA_PASSWORD) ?: ""
            val forceTls12 = intent.getBooleanExtra(EXTRA_FORCE_TLS_12, false)
            val udpgwEnabled = intent.getBooleanExtra(EXTRA_UDPGW_ENABLED, true)
            val udpgwPort = intent.getIntExtra(EXTRA_UDPGW_PORT, 7300)
            val dnsServer = intent.getStringExtra(EXTRA_DNS_SERVER) ?: "1.1.1.1"

            if (!isRunning.get()) {
                startVpn(host, port, sni, payload, enableCamouflage, user, pass, forceTls12, udpgwEnabled, udpgwPort, dnsServer)
            }
            return START_STICKY
        }

        return START_NOT_STICKY
    }

    private fun startVpn(host: String, port: Int, sni: String, payload: String, enableCamouflage: Boolean, user: String, pass: String, forceTls12: Boolean, udpgwEnabled: Boolean, udpgwPort: Int, dnsServer: String) {
        log("Starting VPN connection to $host:$port")
        if (sni.isNotEmpty()) log("SNI: $sni")
        log("Camouflage: $enableCamouflage")
        if (enableCamouflage && payload.isNotEmpty()) log("Payload: [Hidden for brevity]")
        log("Force TLS 1.2: $forceTls12")
        log("UDPGW: $udpgwEnabled (Port: $udpgwPort)")
        log("DNS Server: $dnsServer")

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
                    runVpnLoop(host, port, sni, payload, enableCamouflage, user, pass, forceTls12, udpgwEnabled, udpgwPort, dnsServer)
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
        releaseWakeLock()
        stopForeground(true)
        updateStatus(STATUS_DISCONNECTED)
        stopSelf()
    }

    private fun runVpnLoop(host: String, port: Int, sni: String, payload: String, enableCamouflage: Boolean, user: String, pass: String, forceTls12: Boolean, udpgwEnabled: Boolean, udpgwPort: Int, dnsServer: String) {
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
        builder.addDnsServer(dnsServer.ifEmpty { "1.1.1.1" })
        builder.setMtu(1050)

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

        // We need the raw file descriptor as an Int for the native library
        // detachFd() returns the FD and closes the Java object, passing ownership to native.
        val vpnFd = vpnInterface?.detachFd() ?: -1
        log("FD detached: $vpnFd")

        // Immediately nullify the Java wrapper to prevent accidental usage or double close
        vpnInterface = null

        if (vpnFd == -1) {
             log("Error: Invalid File Descriptor.")
             tunnel?.close()
             return
        }

        log("Starting Tun2Socks Native...")
        try {
            // Generate config file for Tun2Socks
            val configFile = File(cacheDir, "tproxy.conf")
            val logFile = File(cacheDir, "tun2socks.log")
            if (logFile.exists()) logFile.delete()

            createConfig(configFile, 10808, logFile)

            log("Generated Tun2Socks config at: ${configFile.absolutePath} (Size: ${configFile.length()} bytes)")

            // Start the native transparent proxy
            // fd: The TUN interface file descriptor
            // config_path: Path to the configuration file
            TProxyService.TProxyStartService(configFile.absolutePath, vpnFd)

            // TProxyStartService blocks until TProxyStopService() is called or error
            log("Tun2Socks has stopped.")
        } catch (e: Exception) {
            log("Tun2Socks Native Error: ${e.message}")
            e.printStackTrace()
        } finally {
            log("VPN Loop Finished")

            // Read and print native logs
            val logFile = File(cacheDir, "tun2socks.log")
            if (logFile.exists()) {
                try {
                    log("--- Tun2Socks Native Logs ---")
                    logFile.useLines { lines -> lines.forEach { log(it) } }
                    log("--- End Native Logs ---")
                } catch (e: Exception) {
                    log("Failed to read native logs: ${e.message}")
                }
            }

            TProxyService.TProxyStopService()
            try {
                tunnel?.close()
            } catch (e: Exception) {}
        }
    }

    private fun createConfig(configFile: File, socksPort: Int, logFile: File) {
        // CRITICAL: The 'udp: udp' line is mandatory for this library version.
        val configContent = """
            tunnel:
              name: tun0
              mtu: 1050
              ipv4: 10.0.0.2
              ipv6: fc00::2
            socks5:
              port: $socksPort
              address: 127.0.0.1
              udp: udp
            misc:
              log-level: debug
              log-file: ${logFile.absolutePath}
        """.trimIndent()

        configFile.writeText(configContent)
        configFile.setReadable(true, false) // Ensure native can read it
        log("Config Generated with UDP support.")
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

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "VPN Connection",
                NotificationManager.IMPORTANCE_DEFAULT
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(serviceChannel)
        }
    }

    private fun startForegroundService() {
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent, PendingIntent.FLAG_IMMUTABLE
        )

        val notification: Notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("D-Tech VPN")
            .setContentText("VPN is connected")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    private fun acquireWakeLock() {
        if (wakeLock == null) {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "DTechVpn::WakeLock")
        }
        if (wakeLock?.isHeld == false) {
            wakeLock?.acquire()
            log("WakeLock acquired")
        }
    }

    private fun releaseWakeLock() {
        if (wakeLock?.isHeld == true) {
            wakeLock?.release()
            log("WakeLock released")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }
}
