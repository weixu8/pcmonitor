package com.cserver.shared;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;


public class JCache {
	private static final String TAG = "JCache";
	private ConcurrentMap<String, JCacheEntry> cMap = null;
	private JCacheEntry cList = null;
	private int numObjects = 0;
	
	private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();
	private final Lock writeLock = rwLock.writeLock();
	
	public JCache(int numObjects) {
		this.numObjects = numObjects;
		cMap = new ConcurrentHashMap<String, JCacheEntry>(this.numObjects, (float)0.75, 16);	
		cList = new JCacheEntry();
		JCacheEntry.initListhead(cList);
	}
	
	public byte[] lookup(String id) {
		JCacheEntry entry = cMap.get(id);
		byte[] data = null;
		
		if (entry != null) {
			data = entry.data;
			try {
				writeLock.lock();
				JCacheEntry.removeEntryList(entry);
				JCacheEntry.insertHeadList(cList, entry);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			} finally {
				writeLock.unlock();
			}
		}
		return data;
	}
	
	public byte[] delete(String id) {
		JCacheEntry entry = cMap.remove(id);
		byte[] data = null;
		if (entry != null) {
			try {
				writeLock.lock();
				JCacheEntry.removeEntryList(entry);
				data = entry.data;
				entry.dispose();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			} finally {
				writeLock.unlock();
			}
		}
		return data;
	}
		
	public void put(String id, byte[] data) {
		JCacheEntry entry = new JCacheEntry();
		JCacheEntry found = null;
		
		entry.id = id;
		entry.data = data;
		
		found = cMap.putIfAbsent(id, entry);
		if (found != null) {
			entry.dispose();
			found.data = data;
		} else {
			try {
				writeLock.lock();
				JCacheEntry.insertHeadList(cList, entry);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			} finally {
				writeLock.unlock();
			}
		}
		
		if (cList.count > this.numObjects) {
			JCacheEntry entryToRemove = null;
			try {
				writeLock.lock();
				
				if ((cList.count > this.numObjects) && (!JCacheEntry.isEmpty(cList))) {
					entryToRemove = JCacheEntry.removeTailList(cList);
					cMap.remove(entryToRemove.id);
					entryToRemove.dispose();
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			} finally {
				writeLock.unlock();
			}
		} 
	}
	
	public static void main(String[] args) {
		JCache cache = new JCache(3);
		for (int i = 0; i < 5; i++) {
			cache.put(Integer.toString(i), new byte[]{1, 2, 3});
		}
		
		for (int i = 0; i < 5; i++) {
			System.out.println("found by id=" + i + " data=" + cache.lookup(Integer.toString(i)));
		}
		
	}
}
