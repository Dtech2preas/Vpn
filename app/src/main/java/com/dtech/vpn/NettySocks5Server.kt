package com.dtech.vpn

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.*
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.codec.socksx.v5.*
import io.netty.util.concurrent.DefaultEventExecutorGroup
import java.net.InetAddress

class NettySocks5Server(
    private val session: Session,
    private val port: Int,
    private val logger: (String) -> Unit
) {
    private var bossGroup: EventLoopGroup? = null
    private var workerGroup: EventLoopGroup? = null
    private var channel: Channel? = null

    fun start() {
        bossGroup = NioEventLoopGroup(1)
        workerGroup = NioEventLoopGroup()

        try {
            val b = ServerBootstrap()
            b.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel::class.java)
                .childHandler(object : ChannelInitializer<SocketChannel>() {
                    override fun initChannel(ch: SocketChannel) {
                        ch.pipeline().addLast(Socks5ServerEncoder.DEFAULT)
                        ch.pipeline().addLast(Socks5InitialRequestDecoder())
                        ch.pipeline().addLast(Socks5InitialRequestHandler())
                        ch.pipeline().addLast(Socks5CommandRequestDecoder())
                        ch.pipeline().addLast(Socks5CommandRequestHandler(session, logger))
                    }
                })

            channel = b.bind(port).sync().channel()
            logger("Netty SOCKS5 Server started on port $port")
        } catch (e: Exception) {
            logger("Failed to start Netty SOCKS5 Server: ${e.message}")
            stop()
        }
    }

    fun stop() {
        bossGroup?.shutdownGracefully()
        workerGroup?.shutdownGracefully()
        channel?.close()
        logger("Netty SOCKS5 Server stopped")
    }
}

@ChannelHandler.Sharable
class Socks5InitialRequestHandler : SimpleChannelInboundHandler<DefaultSocks5InitialRequest>() {
    override fun channelRead0(ctx: ChannelHandlerContext, msg: DefaultSocks5InitialRequest) {
        // We only support NO_AUTH (0x00)
        ctx.writeAndFlush(DefaultSocks5InitialResponse(Socks5AuthMethod.NO_AUTH))
    }
}

@ChannelHandler.Sharable
class Socks5CommandRequestHandler(
    private val session: Session,
    private val logger: (String) -> Unit
) : SimpleChannelInboundHandler<DefaultSocks5CommandRequest>() {

    // Executor group for blocking SSH operations
    private val sshExecutor = DefaultEventExecutorGroup(16)

    override fun channelRead0(ctx: ChannelHandlerContext, msg: DefaultSocks5CommandRequest) {
        if (msg.type() == Socks5CommandType.CONNECT) {
            handleConnect(ctx, msg)
        } else if (msg.type() == Socks5CommandType.UDP_ASSOCIATE) {
            handleUdpAssociate(ctx, msg)
        } else {
            ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.COMMAND_UNSUPPORTED, Socks5AddressType.IPv4))
        }
    }

    private fun handleConnect(ctx: ChannelHandlerContext, msg: DefaultSocks5CommandRequest) {
        val destAddr = msg.dstAddr()
        val destPort = msg.dstPort()

        sshExecutor.submit {
            try {
                // Inside the CONNECT handling logic...
                val channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP

                // Reflection to invoke package-private setters if needed, or just use public API if available.
                // Assuming standard JSch might need reflection for setHost/setPort if they are protected/package-private
                // but ChannelDirectTCPIP usually exposes setHost/setPort.
                // However, based on the previous Socks5Proxy code, it used reflection.
                // The user instruction snippet says:
                // channel.setHost(destAddr)
                // channel.setPort(destPort)
                // So I will try to call them directly. If they are not accessible, I might need reflection.
                // mwiede/jsch 0.2.20 usually has them public or accessible?
                // Actually, the user snippet calls them directly. I will follow the snippet.

                channel.setHost(destAddr)
                channel.setPort(destPort)
                channel.connect(5000)

                // FIX: Define the streams explicitly
                val sshIn = channel.inputStream
                val sshOut = channel.outputStream

                // Reply Success to client
                ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.SUCCESS, Socks5AddressType.IPv4))

                // Now the rest of your logic (copying sshIn -> Netty Context) will work.

                // We need to bridge the Netty Channel and the SSH Streams.
                // 1. SSH InputStream -> Netty Channel (Write to Client)
                val t1 = Thread {
                    val buffer = ByteArray(8192)
                    try {
                        while (true) {
                            val read = sshIn.read(buffer)
                            if (read == -1) break
                            val data = ctx.alloc().buffer(read)
                            data.writeBytes(buffer, 0, read)
                            ctx.writeAndFlush(data)
                        }
                    } catch (e: Exception) {
                        // EOF or Error
                    } finally {
                        ctx.close()
                    }
                }
                t1.start()

                // 2. Netty Channel (Read from Client) -> SSH OutputStream
                // We need to change the pipeline to forward data to SSH
                ctx.pipeline().remove(Socks5CommandRequestDecoder::class.java)
                ctx.pipeline().remove(this) // Remove the command handler

                ctx.pipeline().addLast(object : SimpleChannelInboundHandler<io.netty.buffer.ByteBuf>() {
                    override fun channelRead0(ctx: ChannelHandlerContext, msg: io.netty.buffer.ByteBuf) {
                        val bytes = ByteArray(msg.readableBytes())
                        msg.readBytes(bytes)
                        try {
                            sshOut.write(bytes)
                            sshOut.flush()
                        } catch (e: Exception) {
                            ctx.close()
                        }
                    }

                    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
                        ctx.close()
                        channel.disconnect()
                    }

                    override fun channelInactive(ctx: ChannelHandlerContext) {
                        channel.disconnect()
                    }
                })

            } catch (e: Exception) {
                logger("Connect failed: ${e.message}")
                ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.FAILURE, Socks5AddressType.IPv4))
                ctx.close()
            }
        }
    }

    private fun handleUdpAssociate(ctx: ChannelHandlerContext, msg: DefaultSocks5CommandRequest) {
        // Bind a dummy UDP port
        // Tun2Socks requires us to return a UDP port where it can send packets.
        // Even if we drop them.

        // We need to reply with the address/port we bound to.
        // For simplicity, we just say we bound to 127.0.0.1 and some random port.
        // But to be "correct", we should actually bind.

        try {
            val udpSocket = java.net.DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
            val port = udpSocket.localPort

            // We don't actually need to read from it, but if we don't, the buffer might fill up?
            // Since it's UDP, packets drop if buffer full.
            // We just let it be. Ideally we should close it when the TCP connection closes.

            ctx.channel().closeFuture().addListener {
                udpSocket.close()
            }

            ctx.writeAndFlush(DefaultSocks5CommandResponse(
                Socks5CommandStatus.SUCCESS,
                Socks5AddressType.IPv4,
                "127.0.0.1",
                port
            ))

            // After UDP ASSOCIATE, the TCP connection must be kept alive.
            // We just remove the handlers that might interpret data and let it idle?
            // Tun2Socks might check if TCP is alive.

            ctx.pipeline().remove(Socks5CommandRequestDecoder::class.java)
            ctx.pipeline().remove(this)

            // Add a handler that ignores everything but keeps connection open
            ctx.pipeline().addLast(object : ChannelInboundHandlerAdapter() {
               // Do nothing on read, effectively black hole for any data on TCP (unlikely for UDP ASSOCIATE)
            })

        } catch (e: Exception) {
             ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.FAILURE, Socks5AddressType.IPv4))
             ctx.close()
        }
    }
}
