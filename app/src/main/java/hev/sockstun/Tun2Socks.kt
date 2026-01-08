package hev.sockstun

class Tun2Socks {
    companion object {
        init {
            try {
                System.loadLibrary("tun2socks")
            } catch (e: UnsatisfiedLinkError) {
                e.printStackTrace()
            }
        }

        @JvmStatic
        external fun run(configPath: String, fd: Int): Int
    }
}
