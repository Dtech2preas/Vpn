# D-Tech VPN Client for Android

A research/educational Android VPN client that implements a custom protocol over TLS.

## ⚠️ Disclaimer

**This is a research project.**
*   It uses a "Trust All" certificate verifier for simplicity and research purposes. **Do not use in production without hardening the TLS verification.**
*   It implements a simple custom handshake: `DTECH-VPN/1.0`.

## Features

*   **VpnService Implementation**: Uses Android's native `VpnService` to capture traffic.
*   **Custom TLS Protocol**: Wraps traffic in a custom TLS tunnel.
*   **Zero Dependencies**: No third-party VPN libraries (no Xray, V2Ray, WireGuard, OpenVPN, etc.). Built purely with Android SDK and Kotlin Standard Library.
*   **Clean Architecture**:
    *   `DTechVpnService`: Core VPN logic, packet reading/writing.
    *   `TlsTunnel`: Manages the SSLSocket and handshake.
    *   `MainActivity`: Simple UI.

## How it Works

1.  **TUN Interface**: The app creates a TUN interface (`10.0.0.2`) to intercept all device traffic.
2.  **TLS Connection**: It opens a standard `SSLSocket` to the user-specified server.
3.  **Handshake**: Sends a custom header (`DTECH-VPN/1.0`) and Token.
4.  **Forwarding**:
    *   Packets read from the TUN interface are written to the TLS socket.
    *   Data received from the TLS socket is written to the TUN interface.

## Build Instructions

1.  **Prerequisites**:
    *   JDK 17
    *   Android SDK

2.  **Build**:
    ```bash
    ./gradlew assembleDebug
    ```

3.  **Install**:
    *   The APK will be located in `app/build/outputs/apk/debug/app-debug.apk`.
    *   Or install directly: `./gradlew installDebug`.
