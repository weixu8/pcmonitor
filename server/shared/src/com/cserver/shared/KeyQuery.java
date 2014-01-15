package com.cserver.shared;

public class KeyQuery {
	public long keyId = -1;
	public int error = Errors.UNSUCCESSFUL;
	public String publicKey = null;	
	public String privateKey = null;
	public String sessionKey = null;
	
	public KeyQuery() {
	}
	
	
	public KeyQuery(int error) {
		this.error = error;
	}
}
