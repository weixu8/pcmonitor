package com.cserver.shared;

public class ErrorException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5389285605494356683L;

	private int error = Errors.UNSUCCESSFUL;
	private String description = null;
	
	public ErrorException(int error) {
		this.error = error;
	}

	public ErrorException(int error, String description) {
		this.error = error;
		this.description = description;
	}
	
	public String getDescription() {
		return this.description;
	}
	
	public int getError() {
		return this.error;
	}
	
	public String toString() {
		return "ErrorException:error=" + this.error + " desc=" + this.description;
	}
}
