package io.github.sagernet.sagernet.bg

object Tun2Socks {
    init { System.loadLibrary("tun2socks") }

    /**
     * SagerNet Start Command.
     * Simple, direct, no config files.
     */
    external fun Start(
        vpnInterfaceFileDescriptor: Int,
        vpnMtu: Int,
        socksServerAddress: String,
        socksServerPort: String,
        dnsServer: String
    )

    external fun Stop()
}
