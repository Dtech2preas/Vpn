package com.dtech.vpn

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import io.netty.bootstrap.ServerBootstrap
import io.netty.bootstrap.Bootstrap
import io.netty.channel.*
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.handler.codec.socksx.v5.*
import io.netty.util.concurrent.DefaultEventExecutorGroup
import io.netty.util.concurrent.EventExecutorGroup
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

class NettySocks5Server(
    private val session: Session,
    private val port: Int,
    private val logger: (String) -> Unit
) {

    private val bossGroup = NioEventLoopGroup(1)
    private val workerGroup = NioEventLoopGroup()
    private val udpGroup = NioEventLoopGroup()
    // Group for blocking I/O (JSch writes)
    private val blockingGroup: EventExecutorGroup = DefaultEventExecutorGroup(16)

    private var channel: Channel? = null
    private val isRunning = AtomicBoolean(false)

    fun start() {
        isRunning.set(true)
        Thread {
            try {
                val b = ServerBootstrap()
                b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel::class.java)
                    .childHandler(object : ChannelInitializer<SocketChannel>() {
                        override fun initChannel(ch: SocketChannel) {
                            // Initial Pipeline: Only Handshake Decoders
                            ch.pipeline().addLast(
                                Socks5ServerEncoder.DEFAULT,
                                Socks5InitialRequestDecoder(),
                                Socks5InitialRequestHandler()
                            )
                        }
                    })

                logger("Starting Netty SOCKS5 Server on 127.0.0.1:$port")
                val f = b.bind("127.0.0.1", port).sync()
                channel = f.channel()
                channel?.closeFuture()?.sync()
            } catch (e: Exception) {
                logger("Netty Server Error: ${e.message}")
            } finally {
                stop()
            }
        }.start()
    }

    fun stop() {
        if (isRunning.compareAndSet(true, false)) {
            logger("Stopping Netty SOCKS5 Server...")
            bossGroup.shutdownGracefully()
            workerGroup.shutdownGracefully()
            udpGroup.shutdownGracefully()
            blockingGroup.shutdownGracefully()
            channel?.close()
        }
    }

    private inner class Socks5InitialRequestHandler : SimpleChannelInboundHandler<Socks5InitialRequest>() {
        override fun channelRead0(ctx: ChannelHandlerContext, msg: Socks5InitialRequest) {
            // Remove Initial Handlers
            ctx.pipeline().remove(Socks5InitialRequestDecoder::class.java)
            ctx.pipeline().remove(this)

            // Add Command Handlers
            ctx.pipeline().addLast(Socks5CommandRequestDecoder())
            // Use blockingGroup here if the command handler itself does blocking work,
            // but we only do blocking work in the CONNECT handler part.
            // For simplicity, we add the CommandHandler to the default group,
            // but offload the CONNECT execution logic.
            ctx.pipeline().addLast(Socks5CommandRequestHandler())

            // Accept NO_AUTH
            ctx.writeAndFlush(DefaultSocks5InitialResponse(Socks5AuthMethod.NO_AUTH))
        }
    }

    private inner class Socks5CommandRequestHandler : SimpleChannelInboundHandler<Socks5CommandRequest>() {
        override fun channelRead0(ctx: ChannelHandlerContext, msg: Socks5CommandRequest) {
            when (msg.type()) {
                Socks5CommandType.CONNECT -> handleConnect(ctx, msg)
                Socks5CommandType.UDP_ASSOCIATE -> handleUdpAssociate(ctx, msg)
                else -> {
                    ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.COMMAND_UNSUPPORTED, msg.dstAddrType()))
                    ctx.close()
                }
            }
        }

        private fun handleConnect(ctx: ChannelHandlerContext, msg: Socks5CommandRequest) {
            val dstAddr = msg.dstAddr()
            val dstPort = msg.dstPort()
            val dstType = msg.dstAddrType()

            // Offload the blocking connection setup to a thread to avoid blocking EventLoop
            Thread {
                var channel: ChannelDirectTCPIP? = null
                try {
                    if (!session.isConnected) {
                        ctx.close()
                        return@Thread
                    }

                    // Inside the CONNECT handling logic...
                    channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                    channel.setHost(dstAddr)
                    channel.setPort(dstPort)
                    channel.connect(5000)

                    // FIX: Define the streams explicitly
                    val sshIn = channel.inputStream
                    val sshOut = channel.outputStream

                    // Reply Success on the Context (Netty Thread)
                    ctx.executor().execute {
                        ctx.writeAndFlush(DefaultSocks5CommandResponse(
                            Socks5CommandStatus.SUCCESS,
                            dstType,
                            dstAddr,
                            dstPort
                        ))

                        // Netty Inbound -> SSH Outbound (Blocking Write)
                        // Remove SOCKS decoders
                        ctx.pipeline().remove(Socks5CommandRequestDecoder::class.java)
                        ctx.pipeline().remove(this)

                        // Add the Blocking Bridge Handler on the blockingGroup
                        ctx.pipeline().addLast(blockingGroup, "sshWriter", object : SimpleChannelInboundHandler<io.netty.buffer.ByteBuf>() {
                            override fun channelRead0(ctx: ChannelHandlerContext, msg: io.netty.buffer.ByteBuf) {
                                val bytes = ByteArray(msg.readableBytes())
                                msg.readBytes(bytes)
                                try {
                                    sshOut.write(bytes) // Blocking
                                    sshOut.flush()
                                } catch (e: Exception) {
                                    ctx.close()
                                }
                            }

                            override fun channelInactive(ctx: ChannelHandlerContext) {
                                try { channel?.disconnect() } catch (e: Exception) {}
                            }
                        })
                    }

                    // SSH Inbound -> Netty Outbound (Blocking Read)
                    // This runs in the Thread we just spawned (or we can spawn another, but this one is free now)
                    val buf = ByteArray(8192)
                    while (true) {
                        val len = sshIn.read(buf) // Blocking
                        if (len == -1) break

                        // We must allocate and write on the Netty Context
                        // Since we are outside the EventLoop, we create a buffer and schedule a write
                        // Note: alloc() is thread-safe.
                        val data = ctx.alloc().buffer(len)
                        data.writeBytes(buf, 0, len)
                        ctx.writeAndFlush(data)
                    }
                    ctx.close()

                } catch (e: Exception) {
                    // logger("Connect Error: ${e.message}")
                    ctx.writeAndFlush(DefaultSocks5CommandResponse(Socks5CommandStatus.FAILURE, dstType))
                    ctx.close()
                    channel?.disconnect()
                }
            }.start()
        }

        private fun handleUdpAssociate(ctx: ChannelHandlerContext, msg: Socks5CommandRequest) {
             val udpBootstrap = Bootstrap()
            udpBootstrap.group(udpGroup)
                .channel(NioDatagramChannel::class.java)
                .handler(object : SimpleChannelInboundHandler<io.netty.channel.socket.DatagramPacket>() {
                    override fun channelRead0(ctx: ChannelHandlerContext, packet: io.netty.channel.socket.DatagramPacket) {
                        // Drop packets
                    }
                })

            val bindFuture = udpBootstrap.bind("127.0.0.1", 0).sync()
            val udpChannel = bindFuture.channel()
            val udpPort = (udpChannel.localAddress() as java.net.InetSocketAddress).port

            // Respond Success
            ctx.writeAndFlush(DefaultSocks5CommandResponse(
                Socks5CommandStatus.SUCCESS,
                Socks5AddressType.IPv4,
                "127.0.0.1",
                udpPort
            ))

             ctx.channel().closeFuture().addListener {
                 udpChannel.close()
             }
        }
    }

    private fun invokePrivateSetter(obj: Any, name: String, type: Class<*>, value: Any) {
        var clazz: Class<*>? = obj.javaClass
         while (clazz != null) {
            try {
                val method = clazz.getDeclaredMethod(name, type)
                method.isAccessible = true
                method.invoke(obj, value)
                return
            } catch (e: NoSuchMethodException) {
                clazz = clazz.superclass
            }
        }
    }
}
