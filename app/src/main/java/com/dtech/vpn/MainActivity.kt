package com.dtech.vpn

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var etHost: EditText
    private lateinit var etPort: EditText
    private lateinit var etSni: EditText
    private lateinit var etPayload: EditText
    private lateinit var etUsername: EditText
    private lateinit var etPassword: EditText
    private lateinit var cbForceTls12: CheckBox
    private lateinit var btnConnect: Button
    private lateinit var btnGeneratePayload: Button
    private lateinit var btnCopyLogs: Button
    private lateinit var btnClearLogs: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvLogs: TextView
    private lateinit var svLogs: ScrollView

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
        etSni = findViewById(R.id.etSni)
        etPayload = findViewById(R.id.etPayload)
        etUsername = findViewById(R.id.etUsername)
        etPassword = findViewById(R.id.etPassword)
        cbForceTls12 = findViewById(R.id.cbForceTls12)
        btnConnect = findViewById(R.id.btnConnect)
        btnGeneratePayload = findViewById(R.id.btnGeneratePayload)
        btnCopyLogs = findViewById(R.id.btnCopyLogs)
        btnClearLogs = findViewById(R.id.btnClearLogs)
        tvStatus = findViewById(R.id.tvStatus)
        tvLogs = findViewById(R.id.tvLogs)
        svLogs = findViewById(R.id.svLogs)

        btnConnect.setOnClickListener {
            if (!isVpnConnected) {
                startVpn()
            } else {
                stopVpn()
            }
        }

        btnGeneratePayload.setOnClickListener {
            generatePayload()
        }

        btnCopyLogs.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("VPN Logs", tvLogs.text)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Logs copied to clipboard", Toast.LENGTH_SHORT).show()
        }

        btnClearLogs.setOnClickListener {
            tvLogs.text = "Ready..."
        }
    }

    private fun generatePayload() {
        // If SNI is present, use it for the Host header (typical for SNI spoofing/CDN tricks)
        // Otherwise use the Server Host
        val host = etHost.text.toString().trim()
        val sni = etSni.text.toString().trim()

        val targetHost = if (sni.isNotEmpty()) sni else host

        if (targetHost.isEmpty()) {
            Toast.makeText(this, "Please enter Host or SNI first", Toast.LENGTH_SHORT).show()
            return
        }

        // Standard Websocket Payload
        val payload = "GET / HTTP/1.1[crlf]Host: $targetHost[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
        etPayload.setText(payload)
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter()
        filter.addAction(DTechVpnService.BROADCAST_LOG)
        filter.addAction(DTechVpnService.BROADCAST_STATUS)

        if (android.os.Build.VERSION.SDK_INT >= 33) {
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
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == Activity.RESULT_OK) {
            val host = etHost.text.toString().trim()
            val portStr = etPort.text.toString().trim()
            val sni = etSni.text.toString().trim()
            val payload = etPayload.text.toString() // No trim, spaces might be significant in payload
            val username = etUsername.text.toString().trim()
            val password = etPassword.text.toString().trim()
            val forceTls12 = cbForceTls12.isChecked

            if (host.isEmpty() || portStr.isEmpty() || username.isEmpty() || password.isEmpty()) {
                Toast.makeText(this, "All fields are required", Toast.LENGTH_SHORT).show()
                return
            }

            val port = try {
                portStr.toInt()
            } catch (e: NumberFormatException) {
                22
            }

            val intent = Intent(this, DTechVpnService::class.java)
            intent.action = DTechVpnService.ACTION_CONNECT
            intent.putExtra(DTechVpnService.EXTRA_HOST, host)
            intent.putExtra(DTechVpnService.EXTRA_PORT, port)
            intent.putExtra(DTechVpnService.EXTRA_SNI, sni)
            intent.putExtra(DTechVpnService.EXTRA_PAYLOAD, payload)
            intent.putExtra(DTechVpnService.EXTRA_USERNAME, username)
            intent.putExtra(DTechVpnService.EXTRA_PASSWORD, password)
            intent.putExtra(DTechVpnService.EXTRA_FORCE_TLS_12, forceTls12)
            startService(intent)
        }
    }

    private fun appendLog(message: String?) {
        message?.let {
            val currentText = tvLogs.text.toString()
            val newText = "$currentText$it\n" // Append to bottom instead of top
            if (newText.length > 50000) { // Increased log limit
                tvLogs.text = newText.substring(newText.length - 50000)
            } else {
                tvLogs.text = newText
            }

            // Auto-scroll to bottom
            svLogs.post {
                svLogs.fullScroll(ScrollView.FOCUS_DOWN)
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
                isVpnConnected = false
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
