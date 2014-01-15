package com.cserver.shared;

public class JRealClock implements IRealClock {
	private long startTime = 0;
	
	public void start() {
		startTime = System.nanoTime();
	}
	
	public long elapsedTime() {
		long currentTime = System.nanoTime();
		return (currentTime - startTime)/1000000;
	}
}
