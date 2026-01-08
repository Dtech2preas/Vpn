package hev.sockstun

class TProxyService {
    companion object {
        init {
            try {
                System.loadLibrary("tun2socks")
            } catch (e: UnsatisfiedLinkError) {
                e.printStackTrace()
            }
        }

        @JvmStatic
        external fun TProxyStartService(configPath: String, fd: Int)

        @JvmStatic
        external fun TProxyStopService()

        @JvmStatic
        external fun TProxyGetStats(): LongArray
    }
}
