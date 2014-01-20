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
    
import java.nio.ByteBuffer;
import java.util.concurrent.Executors;

/**
 * Discards any incoming data.
 */

class ClientPacket
{
	private static final String TAG = "ClientPacket";
	public int type = -1;
	public int status = -1;
	public long txId = -1;
	public int txNum = -1;
	public int dataSize = -1;
	public byte[] data = null;
	
	public ClientPacket() {
		
	}
	
	public static int getSize() {
		return 4*4 + 8;
	}
	
	public boolean decode(byte[] input) {
		if (input.length < getSize()) {
			SLogger.e(TAG, "invalid input.length=" + input.length);
			return false;
		}
		
		ByteBuffer bb = ByteBuffer.wrap(input);
		
		long txId = bb.getLong();
		int txNum = bb.getInt();		
		int type = bb.getInt();
		int status = bb.getInt();
		int dataSize = bb.getInt();
		
		if (dataSize < 0) {
			SLogger.e(TAG, "invalid dataSize=" + dataSize);
			return false;
		}
		
		if (input.length != (getSize() + dataSize)) {
			SLogger.e(TAG, "invalid input.length=" + input.length + " with dataSize=" + dataSize);
			return false;
		}
		
		this.type = type;
		this.status = status;
		this.txId = txId;
		this.txNum = txNum;
		this.dataSize = dataSize;
		
		if (this.dataSize > 0) {
			this.data = new byte[this.dataSize];
			bb.get(this.data);
		} else {
			this.data = null;
		}
		
		return true;
	}
	
	public byte[] encode() {
		if (this.data != null)
			this.dataSize = this.data.length;
		else
			this.dataSize = 0;
		
		byte[] output = new byte[getSize() + this.dataSize];
		ByteBuffer bb = ByteBuffer.wrap(output);
		bb.putLong(txId);
		bb.putInt(txNum);
		bb.putInt(type);
		bb.putInt(status);
		bb.putInt(dataSize);
		if (data != null)
			bb.put(data);
		
		return output;
	}
	public String toString() {
		String output = "";
		output+=" type=" + this.type + " status=" + this.status + " dataSize=" + this.dataSize;
		if (this.data != null)
			output+= " data=" + Utils.bytesToHex(data);
		else
			output+= " data=null";
		
		return output;
	}
}
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
				ClientPacket request = new ClientPacket();
				if (!request.decode(input)) {
					SLogger.e(TAG, "cant decode input=" + Utils.bytesToHex(input));
					return null;
				}
				
				SLogger.i(TAG, "request=" + request.toString());
								
				return request.encode();
			}
        },
        "D:\\pcmonitor\\keys\\ssl_server.jks",
        "1q2w3e",
        "1q2w3e",
        "JKS"
        );
    }
}