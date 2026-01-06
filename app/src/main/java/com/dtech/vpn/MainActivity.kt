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
    private lateinit var btnCopyLogs: Button
    private lateinit var btnClearLogs: Button
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
        etSni = findViewById(R.id.etSni)
        etPayload = findViewById(R.id.etPayload)
        etUsername = findViewById(R.id.etUsername)
        etPassword = findViewById(R.id.etPassword)
        cbForceTls12 = findViewById(R.id.cbForceTls12)
        btnConnect = findViewById(R.id.btnConnect)
        btnCopyLogs = findViewById(R.id.btnCopyLogs)
        btnClearLogs = findViewById(R.id.btnClearLogs)
        tvStatus = findViewById(R.id.tvStatus)
        tvLogs = findViewById(R.id.tvLogs)

        btnConnect.setOnClickListener {
            if (!isVpnConnected) {
                startVpn()
            } else {
                stopVpn()
            }
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
            val newText = "$it\n$currentText"
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
