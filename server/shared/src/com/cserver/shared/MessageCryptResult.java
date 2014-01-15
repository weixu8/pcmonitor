package com.cserver.shared;

public class MessageCryptResult {
	public byte[] encrypted = null;
	public int error = Errors.UNSUCCESSFUL;
	public Message msg = null;
	public long encKeyId = -1;
	
	public MessageCryptResult(int error) {
		this.error = error;
	}

	public MessageCryptResult() {
		// TODO Auto-generated constructor stub
	}
}
