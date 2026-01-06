package com.dtech.vpn.net

import java.nio.ByteBuffer

class Packet(val data: ByteArray, val length: Int) {
    // IPv4 Header
    val version: Int = (data[0].toInt() shr 4) and 0xF
    val protocol: Int = data[9].toInt() and 0xFF
    val sourceAddress: String = ipToString(data, 12)
    val destinationAddress: String = ipToString(data, 16)
    val headerLength: Int = (data[0].toInt() and 0xF) * 4

    // TCP/UDP Ports (Offsets depend on header length, but standard is 20)
    // We only access these if protocol matches
    var sourcePort: Int = 0
    var destinationPort: Int = 0
    var payloadOffset: Int = 0
    var payloadSize: Int = 0

    // TCP Flags
    var isSyn: Boolean = false
    var isAck: Boolean = false
    var isFin: Boolean = false
    var isRst: Boolean = false
    var isPsh: Boolean = false
    var seqNum: Long = 0
    var ackNum: Long = 0

    init {
        if (version == 4) {
            if (protocol == 6) { // TCP
                sourcePort = ((data[headerLength].toInt() and 0xFF) shl 8) or (data[headerLength + 1].toInt() and 0xFF)
                destinationPort = ((data[headerLength + 2].toInt() and 0xFF) shl 8) or (data[headerLength + 3].toInt() and 0xFF)

                val seqNumRaw = ByteBuffer.wrap(data, headerLength + 4, 4).int.toLong() and 0xFFFFFFFFL
                seqNum = seqNumRaw
                val ackNumRaw = ByteBuffer.wrap(data, headerLength + 8, 4).int.toLong() and 0xFFFFFFFFL
                ackNum = ackNumRaw

                val flags = data[headerLength + 13].toInt()
                isFin = (flags and 0x01) != 0
                isSyn = (flags and 0x02) != 0
                isRst = (flags and 0x04) != 0
                isPsh = (flags and 0x08) != 0
                isAck = (flags and 0x10) != 0

                val dataOffset = (data[headerLength + 12].toInt() shr 4) and 0xF
                payloadOffset = headerLength + (dataOffset * 4)
                payloadSize = length - payloadOffset
            } else if (protocol == 17) { // UDP
                sourcePort = ((data[headerLength].toInt() and 0xFF) shl 8) or (data[headerLength + 1].toInt() and 0xFF)
                destinationPort = ((data[headerLength + 2].toInt() and 0xFF) shl 8) or (data[headerLength + 3].toInt() and 0xFF)
                payloadOffset = headerLength + 8
                payloadSize = length - payloadOffset
            }
        }
    }

    private fun ipToString(data: ByteArray, offset: Int): String {
        return "${data[offset].toInt() and 0xFF}.${data[offset+1].toInt() and 0xFF}.${data[offset+2].toInt() and 0xFF}.${data[offset+3].toInt() and 0xFF}"
    }
}
