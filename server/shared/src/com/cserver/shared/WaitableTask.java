package com.cserver.shared;

public interface WaitableTask extends Runnable {
	void waitForComplete();
}
