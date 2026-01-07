package com.dtech.vpn

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import kotlin.math.min

/**
 * Implements a minimal WebSocket Framing Layer (RFC 6455).
 * Designed to wrap an existing InputStream/OutputStream to transparently frame data.
 */
class WebSocketInputStream(private val inner: InputStream) : InputStream() {
    private var buffer: ByteArray = ByteArray(0)
    private var bufferPos = 0
    private val maskKey = ByteArray(4)

    override fun read(): Int {
        val b = ByteArray(1)
        val read = read(b, 0, 1)
        if (read == -1) return -1
        return b[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (availableInFrame() <= 0) {
            // Read next frame
            if (!readNextFrame()) {
                return -1 // EOF
            }
        }

        val toRead = min(len, buffer.size - bufferPos)
        System.arraycopy(buffer, bufferPos, b, off, toRead)
        bufferPos += toRead
        return toRead
    }

    private fun availableInFrame(): Int {
        return buffer.size - bufferPos
    }

    /**
     * Reads the next WebSocket frame from the wire.
     * Returns true if a frame with payload was read, false on EOF or Close.
     */
    private fun readNextFrame(): Boolean {
        // Clear buffer
        buffer = ByteArray(0)
        bufferPos = 0

        // 1. Read first byte (FIN, RSV, Opcode)
        val b1 = inner.read()
        if (b1 == -1) return false

        // val fin = (b1 and 0x80) != 0
        val opcode = b1 and 0x0F

        // 2. Read second byte (Mask, Payload Len)
        val b2 = inner.read()
        if (b2 == -1) return false

        val masked = (b2 and 0x80) != 0
        var payloadLen = (b2 and 0x7F).toLong()

        // 3. Read extended payload length if needed
        if (payloadLen == 126L) {
            val b3 = inner.read()
            val b4 = inner.read()
            if (b3 == -1 || b4 == -1) return false
            payloadLen = ((b3 shl 8) or b4).toLong()
        } else if (payloadLen == 127L) {
            // 8 bytes length (only support reasonable sizes)
            // We ignore the high 4 bytes for simplicity as we can't allocate arrays that big anyway
            for (i in 0 until 4) inner.read() // Skip high bytes
            val bLow = ByteArray(4)
            if (readFull(bLow) < 4) return false
            payloadLen = (((bLow[0].toInt() and 0xFF) shl 24) or
                          ((bLow[1].toInt() and 0xFF) shl 16) or
                          ((bLow[2].toInt() and 0xFF) shl 8) or
                          (bLow[3].toInt() and 0xFF)).toLong()
        }

        // 4. Read Masking Key (if masked)
        if (masked) {
            if (readFull(maskKey) < 4) return false
        }

        // Handle Control Frames (Ping/Pong/Close)
        // Opcode 0x8 (Close), 0x9 (Ping), 0xA (Pong)
        if (opcode == 0x8) {
             return false // Close
        }

        // We ignore Ping/Pong payload for now or handle them?
        // If it's a control frame, we should theoretically process it and read the next frame.
        // But for this specific SSH tunnel use-case, usually we just see Binary frames (0x2).
        // If we get a Ping, we should read the payload and discard it, then recurse.
        if (opcode != 0x0 && opcode != 0x1 && opcode != 0x2) {
             // Skip payload
             skipBytes(payloadLen)
             return readNextFrame()
        }

        // 5. Read Payload
        if (payloadLen > Int.MAX_VALUE - 8) {
            throw IOException("Frame too large")
        }
        val len = payloadLen.toInt()
        val payload = ByteArray(len)
        if (readFull(payload) < len) return false

        // 6. Unmask if needed
        if (masked) {
            for (i in 0 until len) {
                payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
            }
        }

        buffer = payload
        bufferPos = 0
        return true
    }

    private fun readFull(buf: ByteArray): Int {
        var read = 0
        while (read < buf.size) {
            val r = inner.read(buf, read, buf.size - read)
            if (r == -1) break
            read += r
        }
        return read
    }

    private fun skipBytes(n: Long) {
        var skipped = 0L
        while (skipped < n) {
            val s = inner.skip(n - skipped)
            if (s <= 0) {
                // fallback if skip returns 0 but not EOF
                if (inner.read() == -1) break
                skipped++
            } else {
                skipped += s
            }
        }
    }
}

class WebSocketOutputStream(private val inner: OutputStream) : OutputStream() {
    private val random = SecureRandom()
    private val maskKey = ByteArray(4)

    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        // Frame format:
        // Byte 0: 1000 0010 (Fin=1, Binary=0x2)
        inner.write(0x82)

        // Generate mask key
        random.nextBytes(maskKey)

        // Byte 1: Mask=1 | Len
        if (len < 126) {
            inner.write(0x80 or len)
        } else if (len <= 65535) {
            inner.write(0x80 or 126)
            inner.write((len shr 8) and 0xFF)
            inner.write(len and 0xFF)
        } else {
            inner.write(0x80 or 127)
            // Write 8 byte len (high 4 bytes 0)
            inner.write(0); inner.write(0); inner.write(0); inner.write(0)
            inner.write((len shr 24) and 0xFF)
            inner.write((len shr 16) and 0xFF)
            inner.write((len shr 8) and 0xFF)
            inner.write(len and 0xFF)
        }

        // Write Mask Key
        inner.write(maskKey)

        // Write Masked Payload
        // To avoid allocation, we mask on the fly or copy?
        // Modifying input array 'b' is bad practice. We must copy or write byte-by-byte.
        // For efficiency, let's allocate a buffer if small, or stream.
        val masked = ByteArray(len)
        for (i in 0 until len) {
            masked[i] = (b[off + i].toInt() xor maskKey[i % 4].toInt()).toByte()
        }
        inner.write(masked)
        inner.flush()
    }
}
