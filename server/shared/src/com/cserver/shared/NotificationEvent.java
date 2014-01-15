package com.cserver.shared;

public class NotificationEvent {
	private boolean wasSignalled = false;
	
	public NotificationEvent() {
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
	    	 
				}
			}
		}
	}

	public void doNotify(){
		synchronized(this){
			wasSignalled = true;
			this.notifyAll();
		}
	}
}
