package com.cserver.shared;

import java.util.ArrayList;
import java.util.List;


public class QTaskQueuePool {
	private List<QTaskQueue> queues;
	private int qAddPos = 0;
	private volatile boolean shutdown = false;
	
	public QTaskQueuePool(int numQueues) {
		queues = new ArrayList<QTaskQueue>();
		for (int i = 0; i < numQueues; i++)
			queues.add(new QTaskQueue());
	}

	public NotificationEvent add(WaitableCompletionTask task, boolean eventRequired)
	{
		int qIndex = 0;
		
		if (shutdown)
			return null;
		
		QTask qtask = new QTask(task);
		NotificationEvent completionEvent = null;
		if (eventRequired) {
			completionEvent = new NotificationEvent();
			completionEvent.reset();
			qtask.setEvent(completionEvent);
		}
		
		synchronized(this) {
			if (!shutdown) {
				qAddPos++;
				if (qAddPos >= queues.size())
					qAddPos = 0;
				qIndex = qAddPos;
				queues.get(qIndex).add(qtask);
			}
		}
		
		return completionEvent;
	}
	
	public void shutdown() {
		synchronized(this) {
			shutdown = true;
		}
		
		for (int i = 0; i < queues.size(); i++)
			queues.get(i).shutdown();
	}
}
