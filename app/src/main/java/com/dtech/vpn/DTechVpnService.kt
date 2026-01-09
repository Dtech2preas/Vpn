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
import android.util.Log
import androidx.core.app.NotificationCompat
import libv2ray.Libv2ray
import org.json.JSONArray
import org.json.JSONObject

class DTechVpnService : VpnService() {

    companion object {
        const val NOTIFICATION_CHANNEL_ID = "vpn_channel"
        const val NOTIFICATION_ID = 1

        const val ACTION_CONNECT = "com.dtech.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.dtech.vpn.DISCONNECT"

        const val BROADCAST_LOG = "com.dtech.vpn.LOG"
        const val BROADCAST_STATUS = "com.dtech.vpn.STATUS"

        // Status constants
        const val STATUS_DISCONNECTED = 0
        const val STATUS_CONNECTING = 1
        const val STATUS_CONNECTED = 2
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var sshTunnel: SshTlsTunnel? = null
    private var vpnThread: Thread? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action

        if (action == ACTION_DISCONNECT || action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        if (action == ACTION_CONNECT) {
            startForegroundService()

            // Extract Intent Extras
            val protocol = intent.getStringExtra("PROTOCOL") ?: "SSH"
            val host = intent.getStringExtra("host") ?: ""
            val port = intent.getIntExtra("port", 443)
            val sni = intent.getStringExtra("sni") ?: ""
            val payload = intent.getStringExtra("payload") ?: ""
            val enableCamouflage = intent.getBooleanExtra("enable_camouflage", false)
            val username = intent.getStringExtra("username") ?: ""
            val password = intent.getStringExtra("password") ?: ""
            val forceTls12 = intent.getBooleanExtra("force_tls12", false)
            val uuid = intent.getStringExtra("UUID") ?: "" // For VLESS/VMess

            // Start the universal VPN logic
            startUniversalVpn(protocol, host, port, sni, payload, enableCamouflage, username, password, forceTls12, uuid)
            return START_STICKY
        }

        return START_NOT_STICKY
    }

    private fun startUniversalVpn(
        protocol: String,
        host: String,
        port: Int,
        sni: String,
        payload: String,
        enableCamouflage: Boolean,
        username: String,
        password: String,
        forceTls12: Boolean,
        uuid: String
    ) {
        if (vpnThread != null) {
            log("VPN already running or starting.")
            return
        }

        vpnThread = Thread {
            try {
                updateStatus(STATUS_CONNECTING)
                log("Starting VPN Service (Protocol: $protocol)...")

                // 1. Establish VPN Interface (TUN)
                val builder = Builder()
                    .setSession("D-Tech VPN")
                    .setMtu(1500)
                    .addAddress("10.0.1.1", 24)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("1.1.1.1")

                // Allow bypassing the VPN
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    builder.setMetered(false)
                }

                vpnInterface = builder.establish()
                if (vpnInterface == null) {
                    log("Failed to establish VPN interface.")
                    stopVpn()
                    return@Thread
                }

                val fd = vpnInterface!!.fd
                log("VPN Interface established (FD: $fd)")

                // 2. Generate Outbound Config based on Protocol
                val outboundJson = when (protocol.uppercase()) {
                    "SSH" -> {
                        log("Mode: Hybrid SSH (JSch + Xray)")
                        // Hybrid Mode: Start JSch locally, point Xray to it
                        sshTunnel = SshTlsTunnel(
                            host, port, sni, payload, enableCamouflage,
                            username, password, forceTls12
                        ) { msg -> log("SSH: $msg") }

                        sshTunnel?.connect() // Blocking call, opens port 10808
                        log("SSH Tunnel Ready. Xray will route through 127.0.0.1:10808")

                        """
                        {
                            "tag": "proxy",
                            "protocol": "socks",
                            "settings": {
                                "servers": [{ "address": "127.0.0.1", "port": 10808 }]
                            }
                        }
                        """
                    }
                    "VLESS" -> {
                        log("Mode: Native VLESS")
                        // Native Mode: Direct connection
                        """
                        {
                            "tag": "proxy",
                            "protocol": "vless",
                            "settings": {
                                "vnext": [{
                                    "address": "$host",
                                    "port": $port,
                                    "users": [{ "id": "$uuid", "encryption": "none" }]
                                }]
                            },
                            "streamSettings": {
                                "network": "ws",
                                "security": "tls",
                                "tlsSettings": { "serverName": "$sni" },
                                "wsSettings": { "path": "/" }
                            }
                        }
                        """
                    }
                    "VMESS" -> {
                        log("Mode: Native VMess")
                        // Native Mode: Direct connection
                        """
                        {
                            "tag": "proxy",
                            "protocol": "vmess",
                            "settings": {
                                "vnext": [{
                                    "address": "$host",
                                    "port": $port,
                                    "users": [{ "id": "$uuid", "alterId": 0 }]
                                }]
                            },
                            "streamSettings": {
                                "network": "ws",
                                "security": "tls",
                                "tlsSettings": { "serverName": "$sni" },
                                "wsSettings": { "path": "/" }
                            }
                        }
                        """
                    }
                    else -> throw IllegalArgumentException("Unknown Protocol: $protocol")
                }

                // 3. Construct Full Xray Config
                val fullConfig = """
                {
                  "log": { "loglevel": "warning" },
                  "inbounds": [{
                    "tag": "tun-in",
                    "protocol": "tun",
                    "settings": { "fd": $fd, "mtu": 1500 }
                  }],
                  "outbounds": [
                    $outboundJson,
                    { "protocol": "freedom", "tag": "direct" }
                  ],
                  "routing": {
                    "rules": [
                      { "type": "field", "outboundTag": "direct", "ip": ["geoip:private"] },
                      { "type": "field", "outboundTag": "proxy", "network": "tcp,udp" }
                    ]
                  }
                }
                """

                log("Starting Xray Core...")
                // 4. Launch Xray
                // Note: startXray is blocking or starts a background process?
                // The library usually starts it in a way that we need to keep the process alive or it handles it.
                // Looking at typical GoMobile wrappers, we might need to be careful.
                // LibXray.startXray usually blocks or runs until stopped.
                // However, the prompt sample showed:
                // Thread { LibXray.startXray(config) }.start()
                // So we are already in a thread (vpnThread).

                Libv2ray.startLoop(fullConfig)

                // If startXray returns immediately (non-blocking), we need to keep this thread alive or monitor status.
                // If it blocks, then we are good.
                // Assuming it might return if it fails or if it's designed to run in background (less likely for GoMobile functions usually).
                // But let's assume it blocks as per typical GoMobile behavior for "Start" functions unless they say "StartAsync".
                // If it returns, we check if we should still be running.

                log("Xray Core exited.")
                if (vpnInterface != null) {
                    stopVpn()
                }

            } catch (e: Exception) {
                log("Error: ${e.message}")
                e.printStackTrace()
                stopVpn()
            }
        }
        vpnThread?.start()

        updateStatus(STATUS_CONNECTED)
    }

    private fun stopVpn() {
        log("Stopping VPN...")
        try {
            Libv2ray.stopLoop()
        } catch (e: Exception) {
            log("Error stopping Xray: ${e.message}")
        }

        try {
            sshTunnel?.close()
        } catch (e: Exception) {
            log("Error closing SSH: ${e.message}")
        }
        sshTunnel = null

        try {
            vpnInterface?.close()
        } catch (e: Exception) { }
        vpnInterface = null

        vpnThread = null // Thread will naturally exit if it was blocked on Xray

        stopForeground(true)
        updateStatus(STATUS_DISCONNECTED)
        stopSelf()
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
            .setContentText("VPN Connected")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        startForeground(NOTIFICATION_ID, notification)
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
