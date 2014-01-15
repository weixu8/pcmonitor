package com.cserver.shared;

public class FileLockTable {
	private static final int bucketsCount = 257;
	private FileLockMap []buckets = null;
	
	
	FileLockTable() {
		buckets = new FileLockMap[bucketsCount];
		for (int i = 0; i < buckets.length; i++) {
			buckets[i] = new FileLockMap();
			buckets[i].bucketNumber = i;
		}
	}
	
	public FileLock getFileLock(String filePath) {
		return buckets[Math.abs(filePath.hashCode())%bucketsCount].getFileLock(filePath);
	}
	
	public void releaseFileLock(FileLock fileLock) {
		buckets[fileLock.bucketNumber].releaseFileLock(fileLock);
	}
}
