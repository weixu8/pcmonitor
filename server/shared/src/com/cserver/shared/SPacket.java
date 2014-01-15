package com.cserver.shared;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import com.cserver.shared.SLogger;

public class SPacket {
	
	private static final int SIGN = 812312347;
	private static final int MAX_BODY_SIZE = 16000000;
	private static final String TAG = "Packet";
	private int size;
	private int sign;
	public byte[] data;
	
	public SPacket(byte [] data) {
		this.sign = SIGN;
		this.data = data;
		this.size = data.length;
	}
	
	static public SPacket readFrom(GZIPInputStream is) throws IOException {
		byte [] header = new byte[8];
		SLogger.d(TAG, "packet header read start");
		if (8 != is.read(header)) {
			SLogger.d(TAG, "header not read");
			throw new IOException("header not read");
		}
		ByteBuffer bb = ByteBuffer.wrap(header);
		int sign = bb.getInt();
		int size = bb.getInt();
		SLogger.d(TAG, "packet header sign=" + sign + " size=" + size);
		if (sign != SIGN) {
			SLogger.d(TAG, "invalid header sign");
			throw new IOException("invalid header sign");
		}
		if (size > MAX_BODY_SIZE) {
			SLogger.e(TAG, "invalid header size=" + size);
			throw new IOException("invalid header size=" + size);
		}
		
		byte [] body = new byte[size];
		int readsize = 0;		
		try {
			int cbytes = 0;
			while (readsize < body.length) {
				SLogger.d(TAG, "packet read body size=" + cbytes);
				cbytes = is.read(body, readsize, body.length-readsize);
				if (cbytes <= 0) {
					break;
				}
				readsize+= cbytes;
			}
		} catch (IOException e) {
			SLogger.exception(TAG, e);
		}
		
		SLogger.d(TAG, "packet read body completed readsize=" + readsize);
		
		if (readsize != body.length) {
			SLogger.e(TAG, "can't read body");
			throw new IOException("can't read body");		
		}
		
		return new SPacket(body);
	}
	
	static public void writeTo(GZIPOutputStream os, SPacket packet) throws IOException {
		byte [] header = new byte[8];
		ByteBuffer bb = ByteBuffer.wrap(header);
		bb.putInt(packet.sign);
		bb.putInt(packet.size);
		
		SLogger.d(TAG, "packet header write start, sign=" + packet.sign + " size=" + packet.size);
		try {
			os.write(header);
		} catch (IOException e) {
			SLogger.exception(TAG, e);
			throw new IOException("can't write header");		
		}
		
		SLogger.d(TAG, "packet body write");
		try {
			os.write(packet.data);
		} catch (IOException e) {
			SLogger.exception(TAG, e);
			throw new IOException("can't write packet body");		
		}
		
		SLogger.d(TAG, "packet body write completed");
		os.flush();
		SLogger.d(TAG, "packet flush completed");
	}
}
