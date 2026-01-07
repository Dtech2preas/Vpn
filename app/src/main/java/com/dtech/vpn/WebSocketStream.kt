package com.dtech.vpn

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import kotlin.math.min

/**
 * Implements a minimal WebSocket Framing Layer (RFC 6455).
 * Designed to wrap an existing InputStream/OutputStream to transparently frame data.
 *
 * Modified to support "Sniff and Bypass" for raw SSH streams (Opcode 3 / "SSH-").
 */
class WebSocketInputStream(
    private val inner: InputStream,
    private val logger: (String) -> Unit = {}
) : InputStream() {
    private var buffer: ByteArray = ByteArray(0)
    private var bufferPos = 0
    private val maskKey = ByteArray(4)

    // Sniffing state
    private var sniffed = false
    private var isRawMode = false
    private val headerBuffer = ByteArray(4)
    private var headerBufferLen = 0
    private var headerBufferPos = 0

    override fun read(): Int {
        val b = ByteArray(1)
        val read = read(b, 0, 1)
        if (read == -1) return -1
        return b[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (!sniffed) {
            checkProtocol()
        }

        if (isRawMode) {
            return readFromStream(b, off, len)
        }

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

    private fun checkProtocol() {
        if (sniffed) return

        // Peek up to 4 bytes
        var readCount = 0
        while (readCount < 4) {
            // We use inner.read directly here because we are populating the buffer
            // for the first time.
            try {
                // If stream blocks, we block. That's fine.
                // If stream is empty/closed, we handle it.
                // We don't want to block indefinitely if there are fewer than 4 bytes available
                // but usually the server sends a banner or a frame immediately.
                // However, read() blocks until input is available.
                // To avoid blocking forever if the server is slow, we might just read one byte
                // and see if it looks like 'S' or valid WS header?
                // But let's stick to the plan: Read 4 bytes.
                // Note: available() is not reliable.

                // We'll try to read 4 bytes. If we get less because of EOF, we stop.
                val r = inner.read(headerBuffer, readCount, 4 - readCount)
                if (r == -1) break
                readCount += r

                // Optimization: If we have read at least 1 byte and it's NOT 'S' (0x53)
                // and looks like a WS frame (0x81, 0x82), we could maybe abort sniffing early?
                // But for safety, let's try to get 4 bytes or wait.
                // Actually, if we are in this constructor, we expect data.
            } catch (e: IOException) {
                break
            }
        }
        headerBufferLen = readCount
        headerBufferPos = 0

        // Check for "SSH-" (0x53 0x53 0x48 0x2D)
        if (headerBufferLen >= 4 &&
            headerBuffer[0] == 0x53.toByte() &&
            headerBuffer[1] == 0x53.toByte() &&
            headerBuffer[2] == 0x48.toByte() &&
            headerBuffer[3] == 0x2D.toByte()) {

            isRawMode = true
            logger("Detected raw SSH Banner (SSH-). Switching to Raw Mode (Bypassing WebSocket Reads).")
        } else {
            isRawMode = false
            // logger("Sniffed ${headerBufferLen} bytes. No SSH banner detected. Continuing with WebSocket.")
        }
        sniffed = true
    }

    /**
     * Reads from the inner stream, consuming the sniffed buffer first if available.
     */
    private fun readFromStream(b: ByteArray, off: Int, len: Int): Int {
        var destOff = off
        var remaining = len
        var totalRead = 0

        // 1. Read from headerBuffer
        if (headerBufferPos < headerBufferLen) {
            val avail = headerBufferLen - headerBufferPos
            val toCopy = min(remaining, avail)
            System.arraycopy(headerBuffer, headerBufferPos, b, destOff, toCopy)
            headerBufferPos += toCopy
            destOff += toCopy
            remaining -= toCopy
            totalRead += toCopy
        }

        if (remaining == 0) return totalRead

        // 2. Read from inner stream
        try {
            val r = inner.read(b, destOff, remaining)
            if (r > 0) {
                totalRead += r
            } else if (r == -1 && totalRead == 0) {
                return -1
            }
        } catch (e: IOException) {
            if (totalRead > 0) return totalRead
            throw e
        }
        return totalRead
    }

    private fun readByteFromStream(): Int {
        if (headerBufferPos < headerBufferLen) {
            return headerBuffer[headerBufferPos++].toInt() and 0xFF
        }
        return inner.read()
    }

    private fun availableInFrame(): Int {
        return buffer.size - bufferPos
    }

    /**
     * Reads the next WebSocket frame from the wire.
     * Returns true if a frame with payload was read, false on EOF or Close.
     */
    private fun readNextFrame(): Boolean {
        while (true) {
            // Clear buffer
            buffer = ByteArray(0)
            bufferPos = 0

            // 1. Read first byte (FIN, RSV, Opcode)
            val b1 = readByteFromStream()
            if (b1 == -1) {
                // logger("WebSocket EOF reading first byte") // Reduced log noise
                return false
            }

            // val fin = (b1 and 0x80) != 0
            val opcode = b1 and 0x0F
            // logger("WS Opcode: $opcode")

            // 2. Read second byte (Mask, Payload Len)
            val b2 = readByteFromStream()
            if (b2 == -1) {
                logger("WebSocket EOF reading second byte")
                return false
            }

            val masked = (b2 and 0x80) != 0
            var payloadLen = (b2 and 0x7F).toLong()

            // 3. Read extended payload length if needed
            if (payloadLen == 126L) {
                val b3 = readByteFromStream()
                val b4 = readByteFromStream()
                if (b3 == -1 || b4 == -1) return false
                payloadLen = ((b3 shl 8) or b4).toLong()
            } else if (payloadLen == 127L) {
                // 8 bytes length (only support reasonable sizes)
                // We ignore the high 4 bytes for simplicity as we can't allocate arrays that big anyway
                for (i in 0 until 4) readByteFromStream() // Skip high bytes
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

            // Handle Control Frames (Ping/Pong/Close) and Unknowns
            // Opcode 0x8 (Close), 0x9 (Ping), 0xA (Pong)

            if (opcode == 0x8) {
                 logger("WebSocket Close Frame received")
                 return false // Close
            }

            // Check for Data Frames (Text=0x1, Binary=0x2)
            if (opcode == 0x1 || opcode == 0x2) {
                // 5. Read Payload
                if (payloadLen > Int.MAX_VALUE - 8) {
                    throw IOException("Frame too large: $payloadLen")
                }
                val len = payloadLen.toInt()
                val payload = ByteArray(len)
                if (readFull(payload) < len) {
                    logger("WebSocket EOF reading payload")
                    return false
                }

                // 6. Unmask if needed
                if (masked) {
                    for (i in 0 until len) {
                        payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
                    }
                }

                buffer = payload
                bufferPos = 0
                return true
            } else {
                // Control frame (0x9, 0xA) or Unknown opcode (e.g. 0x3)
                // Skip payload and continue loop
                logger("Skipping control frame or unknown opcode: $opcode, len: $payloadLen")
                skipBytes(payloadLen)
                // Loop continues to read next frame
            }
        }
    }

    private fun readFull(buf: ByteArray): Int {
        var read = 0
        while (read < buf.size) {
            val r = readFromStream(buf, read, buf.size - read)
            if (r == -1) break
            read += r
        }
        return read
    }

    private fun skipBytes(n: Long) {
        var skipped = 0L
        while (skipped < n) {
            // We use readByteFromStream to ensure we consume from buffer if needed
            // Skipping by reading is safer with our mixed buffer setup
            val b = readByteFromStream()
            if (b == -1) break
            skipped++
        }
    }
}

class WebSocketOutputStream(
    private val inner: OutputStream,
    private val logger: (String) -> Unit = {}
) : OutputStream() {
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
