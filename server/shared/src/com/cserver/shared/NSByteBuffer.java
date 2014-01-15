package com.cserver.shared;

import java.nio.ByteBuffer;
import java.util.List;

public class NSByteBuffer {
	public byte[] bytes = null;
	public int numBytes = -1;
	
	public NSByteBuffer(byte[] bytes, int numBytes) {
		this.bytes = bytes;
		this.numBytes = numBytes;
	}
	
	public static NSByteBuffer alloc(int numBytes) {
		return new NSByteBuffer(new byte[numBytes], numBytes);
	}
	
	public static byte[] getBytesFromList(List<NSByteBuffer> bbList) {
		int numBytes = 0;
		for (NSByteBuffer bb : bbList) {
			numBytes+= bb.numBytes;
		}
		
		byte[] output = new byte[numBytes];
		ByteBuffer outputBB = ByteBuffer.wrap(output);
		for (NSByteBuffer bb : bbList) {
			outputBB.put(bb.bytes, 0, bb.numBytes);
		}
		
		return outputBB.array();
	}
	
	public static String bbToString(byte [] arr) {
		String output = "[";
		for (int i = 0; i < arr.length; i++)
			output+= " " + arr[i];
		
		return output + "]";
	}
}
