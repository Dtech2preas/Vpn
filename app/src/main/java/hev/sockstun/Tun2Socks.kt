package hev.sockstun

object Tun2Socks {
    init {
        System.loadLibrary("tun2socks")
    }

    /**
     * The Native Library expects a File Descriptor (Int) and a Config Path (String).
     * It does NOT support the 5-argument Start() function we were using.
     */
    external fun run(configPath: String, vpnFd: Int)
    external fun stop()
}
