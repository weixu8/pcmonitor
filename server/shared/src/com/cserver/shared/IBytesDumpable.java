package com.cserver.shared;

public interface IBytesDumpable {
	byte[] toBytes();
	boolean parseBytes(byte[] bytes);
}
