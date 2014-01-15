package com.cserver.shared;

import java.util.ArrayList;
import java.util.List;
public class QTaskQueue implements Runnable {
  private List<QTask> tasks;
  private volatile boolean shutdown;
  private Thread thread;
  static final String TAG = "QTaskQueue";
	
  public QTaskQueue() { 
	  tasks = new ArrayList<QTask>();
	  shutdown = false;
	  thread = new Thread(this);
	  thread.start();
  }
  
  public void add(QTask qtask)
  {
	  synchronized(this) {
		  if (!shutdown) {	
		  	this.tasks.add(qtask);
		  	this.notifyAll();
		  	//SLogger.v(TAG, "task added, task length=" + this.tasks.size() + " " + this);
		  }
	  } 	  
  }

  public int getSize() {
	  int size = 0;
	  synchronized(this) {
		  size = this.tasks.size();
	  }
	  return size;
  }
  
  public void shutdown() {
	  synchronized(this) {
		  shutdown = true;
		  this.notifyAll();
	  }
	  
	  try {
		  thread.join();
	  } catch (InterruptedException e) {
		// TODO Auto-generated catch block
		SLogger.exception(TAG, e);
	  }
	  SLogger.i(TAG, "thread shutdown");
  }
  
  public void run()
  {
	SLogger.i(TAG, "thread run");
    while(!shutdown)
    {
    	QTask task = null;
    	//SLogger.v(TAG, "loop");

    	synchronized(this) {
        	//SLogger.v(TAG, "tasks count=" + this.tasks.size() + " " + this);
    		if (!shutdown && this.tasks.size() == 0) {
    			try {
					this.wait();
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					SLogger.exception(TAG, e);
				}
    		}
    	}
    	
    	synchronized(this) {
    		if (!shutdown && (this.tasks.size() > 0)) {
    			task = this.tasks.get(0);
      			this.tasks.remove(0);
      			//SLogger.v(TAG, "task fetched");
    		} 
    	}
    	
    	if (task != null) {
    		//SLogger.v(TAG, "task will run");
    		task.run();
    	}
    } 
  }
}