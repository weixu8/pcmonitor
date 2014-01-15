package com.cserver.server;

import com.cserver.shared.SLogger;

public abstract class ServerThread implements Runnable {
	private static final String TAG = "ServerThread";
	private Thread thread = null;
	protected volatile boolean stopping = false;
	
	ServerThread() {
		thread = new Thread(this);
	}
	
	protected void stop() {
		stopping = true;
	}
	
	protected void start() {
		thread.start();
	}
	
	public void join() {
		boolean died = false;
		while (!died) {
			try {
				thread.join();
				died = true;
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}
		}
		
	}
}
