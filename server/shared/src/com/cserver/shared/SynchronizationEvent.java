package com.cserver.shared;
public class SynchronizationEvent {
	private static final String TAG = null;
	private boolean wasSignalled = false;
	
	public SynchronizationEvent() {
		this.wasSignalled = false;
	}
	
	public void reset() {
		synchronized(this) {
			this.wasSignalled = false;
		}
	}
	
	public void doWait(){
		synchronized(this){
			while(!wasSignalled){
				try{
					this.wait();
				} catch(InterruptedException e){
					SLogger.exception(TAG, e);
				}
			}
			wasSignalled = false;
		}
	}

	public void doNotify(){
		synchronized(this){
			wasSignalled = true;
			this.notify();
		}
	}
}
