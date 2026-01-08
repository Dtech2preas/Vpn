package hev.sockstun

object Tun2Socks {
    init {
        System.loadLibrary("tun2socks")
    }

    external fun Start(vpnFd: Int, proxyUrl: String, netFd: Int, dns: String, mtu: Int)
    external fun Stop()
}
