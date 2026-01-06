package com.dtech.vpn

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var etHost: EditText
    private lateinit var etPort: EditText
    private lateinit var etToken: EditText
    private lateinit var btnConnect: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvLogs: TextView

    private val VPN_REQUEST_CODE = 100
    private var isVpnConnected = false

    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == DTechVpnService.BROADCAST_LOG) {
                val message = intent.getStringExtra("log")
                appendLog(message)
            } else if (intent?.action == DTechVpnService.BROADCAST_STATUS) {
                val status = intent.getIntExtra("status", DTechVpnService.STATUS_DISCONNECTED)
                updateStatusUI(status)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etHost = findViewById(R.id.etHost)
        etPort = findViewById(R.id.etPort)
        etToken = findViewById(R.id.etToken)
        btnConnect = findViewById(R.id.btnConnect)
        tvStatus = findViewById(R.id.tvStatus)
        tvLogs = findViewById(R.id.tvLogs)

        btnConnect.setOnClickListener {
            if (!isVpnConnected) {
                startVpn()
            } else {
                stopVpn()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter()
        filter.addAction(DTechVpnService.BROADCAST_LOG)
        filter.addAction(DTechVpnService.BROADCAST_STATUS)
        // Register receiver with the appropriate flag for Android 14+ if needed,
        // though regular registerReceiver is fine for standard broadcast.
        // Starting Android 14 (API 34), context-registered receivers need flags.
        // However, we are targeting API 34, so we should be careful.
        // But since we are receiving our own broadcast, default is fine usually,
        // or we use Context.RECEIVER_EXPORTED / RECEIVER_NOT_EXPORTED.

        if (android.os.Build.VERSION.SDK_INT >= 33) { // Android 13+
             registerReceiver(logReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
             registerReceiver(logReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        unregisterReceiver(logReceiver)
    }

    private fun startVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            onActivityResult(VPN_REQUEST_CODE, Activity.RESULT_OK, null)
        }
    }

    private fun stopVpn() {
        val intent = Intent(this, DTechVpnService::class.java)
        intent.action = DTechVpnService.ACTION_DISCONNECT
        startService(intent)
        // UI will update via broadcast
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == Activity.RESULT_OK) {
            val host = etHost.text.toString().trim()
            val portStr = etPort.text.toString().trim()
            val token = etToken.text.toString().trim()

            if (host.isEmpty() || portStr.isEmpty()) {
                Toast.makeText(this, "Host and Port are required", Toast.LENGTH_SHORT).show()
                return
            }

            val port = try {
                portStr.toInt()
            } catch (e: NumberFormatException) {
                443
            }

            val intent = Intent(this, DTechVpnService::class.java)
            intent.action = DTechVpnService.ACTION_CONNECT
            intent.putExtra(DTechVpnService.EXTRA_HOST, host)
            intent.putExtra(DTechVpnService.EXTRA_PORT, port)
            intent.putExtra(DTechVpnService.EXTRA_TOKEN, token)
            startService(intent)
        }
    }

    private fun appendLog(message: String?) {
        message?.let {
            val currentText = tvLogs.text.toString()
            val newText = "$it\n$currentText"
            // Keep log size manageable
            if (newText.length > 5000) {
                tvLogs.text = newText.substring(0, 5000)
            } else {
                tvLogs.text = newText
            }
        }
    }

    private fun updateStatusUI(status: Int) {
        when (status) {
            DTechVpnService.STATUS_CONNECTED -> {
                isVpnConnected = true
                tvStatus.text = getString(R.string.status_connected)
                btnConnect.text = getString(R.string.disconnect)
            }
            DTechVpnService.STATUS_CONNECTING -> {
                isVpnConnected = false // Intermediate state
                tvStatus.text = getString(R.string.status_connecting)
                btnConnect.text = "..."
                btnConnect.isEnabled = false
            }
            DTechVpnService.STATUS_DISCONNECTED -> {
                isVpnConnected = false
                tvStatus.text = getString(R.string.status_disconnected)
                btnConnect.text = getString(R.string.connect)
                btnConnect.isEnabled = true
            }
        }
    }
}
