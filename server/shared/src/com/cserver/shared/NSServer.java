package com.cserver.shared;


import javax.net.ssl.SSLEngine;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslHandler;
    
import java.util.concurrent.Executors;

/**
 * Discards any incoming data.
 */
public class NSServer {
    
    private static final String TAG = "NSServer";
	private int port = -1;
    
    public NSServer(int port) {
        this.port = port;
    }
    
    public void run(final INSServerHandler handler, final String ksPath, final String ksPass, final String keyPass, final String ksType) throws Exception {
        EventLoopGroup bossGroup = new NioEventLoopGroup(); // (1)
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {
            ServerBootstrap b = new ServerBootstrap(); // (2)
            b.group(bossGroup, workerGroup)
             .channel(NioServerSocketChannel.class) // (3)
             .childHandler(new ChannelInitializer<SocketChannel>() { // (4)
                 @Override
                 public void initChannel(SocketChannel ch) throws Exception {
                	 if (ksPath != null) {
                		 SSLEngine engine = SSLSocketLib.createSSLEngine(ksPath, ksPass, keyPass, ksType);
                		 ch.pipeline().addLast("ssl", new SslHandler(engine));
                	 }
                     ch.pipeline().addLast(new NSServerHandler(handler, Executors.newCachedThreadPool()));
                 }
             })
             .option(ChannelOption.SO_BACKLOG, 10000)          // (5)
             .childOption(ChannelOption.SO_KEEPALIVE, true); // (6)
    
            // Bind and start to accept incoming connections.
            ChannelFuture f = b.bind(port).sync(); // (7)
    
            // Wait until the server socket is closed.
            // In this example, this does not happen, but you can do that to gracefully
            // shut down your server.
            f.channel().closeFuture().sync();
        } finally {
            workerGroup.shutdownGracefully();
            bossGroup.shutdownGracefully();
        }
    }
    
    public static void main(String[] args) throws Exception {
    	SLogger.start(false, "D:\\pcmonitor\\logs\\NSServer.log.txt", null);
    	SLogger.i(TAG, "server starting...");
        NSServer server = new NSServer(9111);
        server.run(new INSServerHandler() {

			@Override
			public byte[] handle(byte[] input) {
				// TODO Auto-generated method stub
				return input;
			}
        },
        "D:\\pcmonitor\\keys\\ssl_server.jks",
        "1q2w3e",
        "1q2w3e",
        "JKS"
        );
    }
}