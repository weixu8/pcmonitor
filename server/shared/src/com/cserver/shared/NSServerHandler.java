package com.cserver.shared;


import java.util.LinkedList;
import java.util.concurrent.ExecutorService;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

/**
 * Handles a server-side channel.
 */

class HandlerExecTask implements Runnable {
	private static final String TAG = "HandlerExecTask";
	private NSServerHandler handler = null;
	private ChannelHandlerContext ctx = null;
	private byte[] input = null;
	
	public HandlerExecTask(NSServerHandler handler, ChannelHandlerContext ctx, byte[] input) {
		this.handler = handler;
		this.ctx = ctx;
		this.input = input;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		try {
			handler.complete(handler.handle(input), ctx);
		} catch (Throwable t) {
			SLogger.throwable(TAG, t);
			handler.exceptionCaught(ctx, t);
		}
	}
}

public class NSServerHandler extends ChannelInboundHandlerAdapter { // (1)

    private static final String TAG = "NSServerHandler";
    private volatile NSPacketHeader header = null;
    private LinkedList<ByteBuf> bbList = new LinkedList<ByteBuf>();
    private INSServerHandler handler = null;
    private ExecutorService exec = null;
    
    public NSServerHandler(INSServerHandler handler, ExecutorService exec) {
    	this.handler = handler;
    	this.exec = exec;
    }
    
    public void complete(byte[] output, ChannelHandlerContext ctx) {
		if (output != null) {
			NSPacketHeader header = new NSPacketHeader(output.length);
			ctx.write(Unpooled.wrappedBuffer(header.toBytes()));
			ctx.writeAndFlush(Unpooled.wrappedBuffer(output));
		} else {
			SLogger.e(TAG, "no output from handler");
			NSPacketHeader header = new NSPacketHeader(0);
			ctx.writeAndFlush(Unpooled.wrappedBuffer(header.toBytes()));
		}
    }
    
    public byte[] handle(byte[] input) {
    	return this.handler.handle(input);
    }
    
    public byte[] readBBList(int size) throws Exception {
    	int readBytes = 0;
    	byte[] input = new byte[size];
    	ByteBuf packetBB = Unpooled.wrappedBuffer(input);
    	packetBB.setIndex(0, 0);

    	while (true) {   		
    		ByteBuf bb = bbList.removeFirst();
    		int cbytes = bb.readableBytes();
    		if (cbytes + readBytes <= size) {
    			if (packetBB.writableBytes() < cbytes)
    				throw new Exception("not enough packetBB writable bytes");   			
    			bb.readBytes(packetBB, cbytes);
    			readBytes+= cbytes;
    			bb.release();
    		} else {
    			cbytes = size - readBytes;
    			if (packetBB.writableBytes() < cbytes)
    				throw new Exception("not enough packetBB writable bytes");   
    			
    			bb.readBytes(packetBB, cbytes);
    			bbList.addFirst(bb);
    			readBytes+= cbytes;
    		}
    			
    		if (readBytes == size)
    			break;
    	}
    	
    	packetBB.release();
    	
    	return input;
    }
    
    public int getBBListSize() {
    	int size = 0;
    	for (ByteBuf bb : bbList) {
    		size+= bb.readableBytes();
    	}
    	return size;
    }
    
    public void processNewBB(ChannelHandlerContext ctx, ByteBuf inputBb) throws Exception {
		bbList.add(inputBb);
    	if (header == null) {
    		if (getBBListSize() >= NSPacketHeader.getHeaderLength()) {
    			byte[] rawHeader = readBBList(NSPacketHeader.getHeaderLength());
    			header = NSPacketHeader.fromBytes(rawHeader);
    			if (header == null) {
    				SLogger.e(TAG, "no header");
    				ctx.close();
    				return;
    			}
    			if (header.size == 0) {
    				SLogger.e(TAG, "no input data");
    				ctx.close();
    				return;
    			}
    		} 
		}
		
		if (header != null && getBBListSize() >= header.size) {
			byte[] input = readBBList(header.size);
			this.exec.submit(new HandlerExecTask(this, ctx, input));
			header = null;
		}	
    }
    
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception { // (2)
        // Discard the received data silently.
    	
		processNewBB(ctx, (ByteBuf)msg);		
    }
	
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) { // (4)
        // Close the connection when an exception is raised.
    	
        SLogger.throwable(TAG, cause);
        ctx.close();
    }
}