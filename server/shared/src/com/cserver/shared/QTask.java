package com.cserver.shared;

public class QTask {
	private WaitableCompletionTask task = null;
	private NotificationEvent event = null;

	public QTask(WaitableCompletionTask task) {
		// TODO Auto-generated constructor stub
		this.task = task;
		this.event = null;
	}

	public void setEvent(NotificationEvent event) {
		synchronized(this) {
			this.event = event;
		}
	}
	
	public void run() {
		// TODO Auto-generated method stub
		NotificationEvent event = null;
		synchronized(this) {
			this.task.run();
			this.task.onComplete();
			if (this.event != null) {
				event = this.event;
				this.event = null;
			}
		}
		
		if (event != null)
			event.doNotify();
		
	}
}
