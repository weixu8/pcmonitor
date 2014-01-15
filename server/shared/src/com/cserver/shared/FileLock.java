package com.cserver.shared;

import java.io.File;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class FileLock {
	public volatile AtomicInteger refCount = new AtomicInteger(1);
	public String filePath = null;
	public int bucketNumber;
	public final ReentrantReadWriteLock readWriteLock = new ReentrantReadWriteLock();
	public final Lock readLock  = readWriteLock.readLock();
	public final Lock writeLock = readWriteLock.writeLock();
	
	private static FileLockTable lockTable = new FileLockTable();
	
	public static FileLock getFileLock(String filePath) {
		File file = new File(filePath);
		return lockTable.getFileLock(file.getAbsolutePath());
	}
	
	public static void releaseFileLock(FileLock fileLock) {
		lockTable.releaseFileLock(fileLock);
	}
}
