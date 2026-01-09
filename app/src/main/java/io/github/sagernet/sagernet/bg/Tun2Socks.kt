package io.github.sagernet.sagernet.bg

object Tun2Socks {
    init {
        System.loadLibrary("tun2socks")
    }

    /**
     * Starts the Tun2Socks VPN service.
     * This function is blocking and will return when the service stops or an error occurs.
     *
     * @param vpnInterfaceFileDescriptor The file descriptor of the VPN interface (TUN).
     * @param vpnMtu The MTU of the VPN interface.
     * @param socksServerAddress The address of the SOCKS5 proxy (e.g., "127.0.0.1").
     * @param socksServerPort The port of the SOCKS5 proxy (e.g., "10808").
     * @param dnsServer The DNS server address to use.
     */
    external fun Start(
        vpnInterfaceFileDescriptor: Int,
        vpnMtu: Int,
        socksServerAddress: String,
        socksServerPort: String,
        dnsServer: String
    )

    /**
     * Optional: Check if Stop exists in your native lib.
     * If not, calling this will crash. Based on standard go-tun2socks, closing the FD is the way to stop.
     * But we include this just in case the memory implied it, though it didn't explicitly.
     * The memory only mentioned Start.
     * I'll leave it out to be safe unless required.
     */
}
