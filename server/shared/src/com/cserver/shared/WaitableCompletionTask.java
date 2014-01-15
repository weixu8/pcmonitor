package com.cserver.shared;

public interface WaitableCompletionTask extends WaitableTask {
	void onComplete();
}
