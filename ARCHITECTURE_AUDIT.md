# Technical Architecture & Data Flow Report

This document provides a comprehensive audit of the application's network stack, tracing the lifecycle of packets, analyzing component behavior, auditing configuration propagation, and identifying potential silent failures.

## 1. The Packet Lifecycle (The 'Flow')

### A. Outgoing Traffic (Android -> Network)

1.  **TUN Read (`DTechVpnService.kt`)**
    *   The OS writes IP packets to the TUN interface (`10.0.0.2`).
    *   `DTechVpnService` reads these packets into a 16KB buffer (`buf`) in a blocking loop.
    *   **Data:** Raw IPv4 Packet.

2.  **Protocol Identification (`Tun2Socks.kt`)**
    *   `processPacket(buffer, length)` is called.
    *   **Check:** `Packet.getIPVersion(buffer) != 4` -> **DROP** (Returns immediately).
    *   **Extraction:** IP Protocol (TCP/UDP), Source IP, Dest IP.

3.  **Decision Logic (Router)**

    *   **UDP Path:**
        *   **Condition:** `protocol == Packet.PROTOCOL_UDP`
        *   **Sub-Decision 1 (DNS):**
            *   **Logic:** `if (dstPort == 53)`
            *   **Action:** `dnsForwarder.processPacket(...)`
            *   **Transport:** Encapsulated in a dedicated SSH `direct-tcpip` channel to the **VPN Server's DNS** (or `customDns` if configured, but see Section 3).
        *   **Sub-Decision 2 (UDPGW):**
            *   **Logic:** `else if (enableUdpGw && udpGwClient != null)`
            *   **Action:** `udpGwClient.processPacket(...)`
            *   **Transport:** Encapsulated in BadVPN-UDPGW protocol over a **single shared SSH `direct-tcpip` channel** pointing to `127.0.0.1:<udpgw_port>`.
        *   **Drop:** If neither above matches, the packet is ignored (Silent Drop).

    *   **TCP Path:**
        *   **Condition:** `protocol == Packet.PROTOCOL_TCP`
        *   **Action:** Checks `connections` map for existing flow (`srcIp:srcPort->dstIp:dstPort`).
        *   **New Flow (SYN):**
            *   **Gating 1:** `if (!isDnsReady.get())` -> **DROP SILENTLY**. (Wait for DNS self-test).
            *   **Gating 2:** `if (connections.size >= MAX_CONCURRENT_TCP)` -> **DROP & LOG**.
            *   **Creation:** Creates `TcpConn`, sends SYN-ACK locally, and launches thread to open SSH `direct-tcpip` channel to the target destination.
        *   **Existing Flow:**
            *   **Action:** `conn.processPacket(...)`.
            *   **Data:** Pushed to `sshOut` (Blocking write).

4.  **Encapsulation (Transport Layer)**
    *   **SSH (JSch):** All traffic (DNS, UDPGW, TCP) is written to JSch streams.
    *   **Framing (`WebSocketOutputStream`):**
        *   If `isRawMode` (SSH detected): Writes raw bytes.
        *   If WebSocket: Wraps data in WS Binary Frames (Opcode 0x82), masks payload, and writes to underlying socket.
    *   **TLS (`SshTlsTunnel`):** Wraps the stream in SSL/TLS (with SNI).
    *   **Network Write:** `sslSocket.outputStream.write(...)`.

### B. Return Traffic (Network -> Android)

1.  **Reading from Network**
    *   **TLS/SSL:** Decrypts incoming bytes.
    *   **Framing (`WebSocketInputStream`):**
        *   Reads frames. If WS, validates Opcode, unmasks (server usually doesn't mask, but logic supports it), extracts payload.
        *   **Filter:** Skips Control Frames (Ping/Pong/Close) and Unknown Opcodes.
    *   **SSH (JSch):** Demultiplexes data to appropriate Channel (TCP, DNS, UDPGW).

2.  **Protocol Handling**

    *   **TCP (`TcpConn`):**
        *   Reading thread (`readLoop`) receives data.
        *   **Action:** Constructs IPv4/TCP packet (PSH+ACK).
        *   **Injection:** Calls `tun2Socks.writePacket(...)`.

    *   **DNS (`DnsForwarder`):**
        *   Receives response on dedicated channel.
        *   **Action:** Constructs IPv4/UDP packet.
        *   **Injection:** Calls `tun2Socks.writePacket(...)`.

    *   **UDPGW (`UdpGwClient`):**
        *   Receives BadVPN frame.
        *   **Action:** Parses header, maps `ConID` back to `ClientIP/Port`.
        *   **Critical Rewrite:** Rewrites Source IP to `originalServerIp` (the IP the client *thought* it was talking to).
        *   **Injection:** Constructs IPv4/UDP packet and calls `tun2Socks.writePacket(...)`.

3.  **Writing to TUN**
    *   `tun2Socks.writePacket` synchronizes on `vpnOutput`.
    *   Writes raw bytes to the TUN file descriptor.
    *   Android OS receives packet and delivers to app.

---

## 2. Component Deep Dive

### Tun2Socks: Interception Logic
**Location:** `app/src/main/java/com/dtech/vpn/net/Tun2Socks.kt`

The decision logic is purely based on **Protocol** and **Port**. IP Address checks are only for IPv4 validation.

```kotlin
// Exact Logic extracted from Tun2Socks.kt

if (protocol == Packet.PROTOCOL_UDP) {
    val dstPort = Packet.getUdpDstPort(buffer, ipHeaderLen)

    // DNS Priority: Intercept Port 53
    if (dstPort == 53) {
        // ... Send to DnsForwarder ...
    } else if (enableUdpGw && udpGwClient != null) {
        // ... Send to UdpGwClient ...
    }
    // ELSE: Implicit Drop (Silent)
}
```

### DNS Forwarder: Processing Model
**Location:** `app/src/main/java/com/dtech/vpn/net/DnsForwarder.kt`

*   **Model:** **One Thread Per Query** (via `Executors.newCachedThreadPool()`).
*   **Connection:** Opens a **new** `direct-tcpip` SSH channel for **every single query**.
    *   `channel.connect(10000)` (10s timeout).
*   **Blocking:** The thread blocks waiting for the SSH channel connect and the response.
*   **Self-Test:** It performs a mandatory self-test (Query ID 0) on startup. `Tun2Socks` **blocks all new TCP connections** until this test passes.

### SSH Transport: Direct-TCPIP
**Location:** `app/src/main/java/com/dtech/vpn/net/TcpConn.kt`

*   **Buffering:** Minimal. Writes directly to `sshOut` inside the `processPacket` synchronized block.
    *   `sshOut?.write(data)`
    *   `sshOut?.flush()`
*   **Blocking:** This write is **blocking**. If the network is slow or the buffer is full, the entire VPN read loop in `DTechVpnService` stalls.

---

## 3. Configuration Audit

### Hardcoded Values vs. User Input

| Parameter | User Input (UI) | Internal Handling | Effective Value |
| :--- | :--- | :--- | :--- |
| **VPN DNS** | `etCustomDns` | Passed to `DTechVpnService` via intent. Defaults to `1.1.1.1` if empty. | **User Defined** (or 1.1.1.1) |
| **UDPGW Port** | `etUdpGwPort` | Passed via intent. Defaults to `7300` if parse fails. | **User Defined** (or 7300) |
| **MTU** | N/A | Hardcoded in `DTechVpnService.kt`. | **1050** |
| **Concurrent TCP** | N/A | Hardcoded in `Tun2Socks.kt`. | **4** |
| **SSH Keepalive** | N/A | Hardcoded in `SshTlsTunnel.kt`. | **15 seconds** |
| **Connect Timeout** | N/A | Hardcoded in `SshTlsTunnel.kt`. | **60 seconds** |

### Critical Findings
1.  **UDPGW DNS Logic:** In `UdpGwClient.kt`, there is logic to override the destination IP for Port 53 traffic inside UDPGW, but `Tun2Socks` intercepts Port 53 **before** it reaches UDPGW. Thus, **DNS traffic never goes through UDPGW**, rendering that logic dead code.
2.  **DNS Forwarder Destination:** `DnsForwarder` uses the `dnsServer` string (passed from `Tun2Socks` -> `DTechVpnService` -> User Input) as the target Host for the `direct-tcpip` channel.
    *   If User inputs `1.1.1.1`, the SSH server attempts to connect to `1.1.1.1:53`.
    *   **Bug Potential:** If the SSH server blocks public DNS or only allows local DNS (e.g., `127.0.0.1`), this will fail.

---

## 4. The 'Silence' Analysis

### Scenario A: UDP Packet Drop (Non-DNS, UDPGW Disabled)
If `enableUdpGw` is false (unchecked in UI), and the user attempts to visit a QUIC-enabled site (YouTube, Google) or use VoIP:
*   Packet enters `Tun2Socks`.
*   `protocol == UDP` -> True.
*   `dstPort == 53` -> False.
*   `enableUdpGw` -> False.
*   **Result:** The `if/else` block ends. The function returns.
*   **Outcome:** **Silent Drop.** No log message ("Packet received" is logged, but no "Dropped" message).

### Scenario B: TCP Connection Blocked by DNS
If the DNS Self-Test fails or hangs (e.g., due to the "Bug Potential" in Section 3):
*   `isDnsReady` remains `false`.
*   User opens a browser (sends TCP SYN).
*   `Tun2Socks` Logic: `if (!isDnsReady.get()) return`.
*   **Outcome:** **Silent Drop.** The SYN is ignored. The browser hangs "Connecting..." indefinitely. No explicit log indicates *why* it was dropped (commented out code: `// logger("Dropped SYN (DNS not ready): $key")`).

### Scenario C: Exception Swallowing
1.  **UDPGW Cleanup:**
    *   In `UdpGwClient.kt`, the `cleanupLoop` swallows all exceptions: `catch (e: Exception) {}`. If the cleanup logic crashes, connections might leak forever.
2.  **SSH Read Loop:**
    *   In `TcpConn.kt`, `readLoop`: `catch (e: Exception) { // logger(...) }`. If the SSH stream dies, it logs nothing (commented out) and silently closes the connection.

### Scenario D: WebSocket Handshake Failure
In `SshTlsTunnel.kt`, `checkAndConsumeHttpResponse`:
*   It reads up to 4096 bytes looking for `\r\n\r\n`.
*   If found, it checks for " 101 ".
*   **If NOT found (e.g., server sends garbage or different header):** It logs a warning but **returns `false`**.
*   The code then proceeds to use the socket **as is**.
*   **Issue:** If the buffer actually contained data that JSch needs (but didn't look like HTTP), that data *might* have been consumed by the `StringBuilder` and **lost** because it's not put back into the stream.
    *   *Correction:* The `InputStream` is passed to JSch. The bytes read into `buffer` (StringBuilder) are **GONE**. If `checkAndConsumeHttpResponse` returns false, JSch starts reading from the *next* byte. The initial bytes are lost. This creates a "Connected but stuck" state if the server didn't send a clean HTTP response.
