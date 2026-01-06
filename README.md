# D-Tech VPN (Research & Educational Tool)

This application is a **Client-Side Tunneling Tool** designed for zero-rated network research and experimentation. It demonstrates the mechanics of **SNI-based TLS Tunneling** (SSH over TLS).

## ⚠️ Important Context

This tool is designed to work in environments where:
*   The ISP or Network Provider allows specific HTTPS traffic (Zero-rated hosts).
*   The decision is made based on the **SNI (Server Name Indication)** field in the TLS ClientHello.
*   **Mobile Data is assumed to be 0MB**, relying solely on the whitelisted host.

## Architecture

This app implements a strict protocol pipeline:

1.  **TCP Connection**: Opens a raw socket to the destination SSH Server.
2.  **TLS Layer (The Gatekeeper)**: Wraps the socket in TLS.
    *   **SNI Injection**: Injects the zero-rated Hostname (e.g., `onlinecms.mtn.co.za`) into the ClientHello to bypass the firewall/billing system.
3.  **Authentication**: Performs a standard TLS Handshake (trusting all certs for research purposes).
4.  **[Optional] HTTP Camouflage**: Sends a dummy HTTP Request (Payload) to mimic a browser or Websocket upgrade. *Note: This requires the server to support HTTP->SSH handoff.*
5.  **SSH Tunnel**: Establishes a standard SSH connection over the TLS tunnel.

## How to Use

1.  **SSH Server**: Enter your SSH Server IP and Port (usually 443 if using Stunnel).
2.  **SNI Host**: **(Required)** Enter the zero-rated SNI Hostname.
3.  **Camouflage**:
    *   **OFF (Default)**: Use this for standard Stunnel/SSH servers. The connection will be `TLS(SNI) -> SSH`.
    *   **ON**: Use this if your server expects a Websocket Upgrade or HTTP Payload before the SSH stream.
4.  **Credentials**: Enter SSH Username and Password.

## Disclaimer

This application is for educational purposes only. It is intended to teach the internal mechanics of VPN protocols, TLS handshakes, and SNI spoofing. It does not contain any built-in free internet exploits or hidden servers.
