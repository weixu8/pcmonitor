package com.cserver.shared;

public interface TaskCompleteCallback {
	public void onTaskComplete(int error, String errorDescription, String extra);
}
