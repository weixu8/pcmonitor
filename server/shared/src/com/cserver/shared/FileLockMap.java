package com.cserver.shared;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class FileLockMap {
	private Map<String, FileLock> map = new HashMap<String, FileLock>();
	private final ReentrantReadWriteLock readWriteLock = new ReentrantReadWriteLock();
	private final Lock readLock  = readWriteLock.readLock();
	private final Lock writeLock = readWriteLock.writeLock();
	public int bucketNumber;
	
	public FileLock getFileLock(String filePath) {
		FileLock fileLock = null;
		
		readLock.lock();
		try {
			fileLock = map.get(filePath);
			if (fileLock != null) {
				fileLock.refCount.incrementAndGet();
			}
		} finally {
			readLock.unlock();
		}
		
		if (fileLock != null)
			return fileLock;

		writeLock.lock();
		try {
			fileLock = map.get(filePath);
			if (fileLock != null) {
				fileLock.refCount.incrementAndGet();
			} else {
				fileLock = new FileLock();
				fileLock.bucketNumber = bucketNumber;
				fileLock.filePath = filePath;
				map.put(filePath, fileLock);
				fileLock.refCount.incrementAndGet();
			}
		} finally {
			writeLock.unlock();
		}
		
		return fileLock;
	}
	
	public void releaseFileLock(FileLock fileLock) {
		if (fileLock.refCount.decrementAndGet() == 1) {
			writeLock.lock();
			try {
				if (fileLock.refCount.get() == 1)
					map.remove(fileLock.filePath);
			} finally {
				writeLock.unlock();
			}
		}
	}
}
