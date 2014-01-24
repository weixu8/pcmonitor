package com.cserver.server;


public class DbResult {
	public int error = ClientRequest.STATUS_ERROR_UNDEFINED;
	
	public DbResult() {
		this.error = ClientRequest.STATUS_ERROR_UNDEFINED;
	}
	
	public DbResult(int error) {
		this.error = error;
	}
}
