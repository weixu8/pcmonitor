package com.cserver.shared;

import java.nio.ByteBuffer;

public class NSPacketHeader {
	private static final String TAG = "NSPacketHeader";
	public int size = -1;
	private static int SIGN = 2134234237;
	
	public NSPacketHeader(int size) {
		this.size = size;
	}
	
	public static int getHeaderLength() {
		return 4*2;
	}
		
	public byte [] toBytes() {
		byte[] header = new byte[getHeaderLength()];
		ByteBuffer bb = ByteBuffer.wrap(header);
		bb.putInt(SIGN);
		bb.putInt(size);
		
		return header;
	}
	
	public static  NSPacketHeader fromBytes(byte[] rawHeader) {
		
		if (rawHeader.length < getHeaderLength()) {
			SLogger.e(TAG, "rawHeader.length=" + rawHeader.length + " incorrect");
			return null;
		}
		
		ByteBuffer bb = ByteBuffer.wrap(rawHeader);
		int sign = bb.getInt();
		if (sign != SIGN) {
			SLogger.e(TAG, "sign=" + sign + " incorrect");
			return null;
		}
		
		NSPacketHeader header = new NSPacketHeader(-1);
		header.size = bb.getInt();
		
		return header;
	}
}
