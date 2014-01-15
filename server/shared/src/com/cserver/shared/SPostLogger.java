package com.cserver.shared;

public interface SPostLogger {
	public void debugMessage(String tag, String message);
	public void errorMessage(String tag, String message);
	public void infoMessage(String tag, String message);
	public void verboseMessage(String tag, String message);	
	public void exceptionMessage(String tag, Exception e);
	public void throwableMessage(String tag, Throwable t);
	public String currentTime();
}
