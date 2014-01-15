package com.cserver.server;

public class JCacheEntry {
	public String id = null;
	public byte[] data = null;
	public JCacheEntry blink = null;
	public JCacheEntry flink = null;
	public JCacheEntry head = null;
	public volatile int count = -1;
	
	public JCacheEntry() {
		
	}
	
	public static void initListhead(JCacheEntry head) {
		head.flink = head.blink = head;
		head.head = head;
		head.count = 0;
	}
	
	public static boolean isHead(JCacheEntry entry) {
		return (entry.head == entry);
	}
	
	public static boolean isEmpty(JCacheEntry head) {
		return (head.flink == head.blink);
	}
	
	private static void raiseInconsistencyError() throws Exception {
		throw new Exception("List inconsistency error!");
	}
	
	private static void checkEntry(JCacheEntry entry) throws Exception {
		if ((entry.flink.blink != entry) || (entry.blink.flink != entry)) {
			raiseInconsistencyError();
		}
	}
	
	public static void insertTailList(JCacheEntry head, JCacheEntry entry) throws Exception {
		JCacheEntry prev = null;
		
		checkEntry(head);
		
		prev = head.blink;
		entry.flink = head;
		entry.blink = prev;
		
		if (prev.flink != head)
			raiseInconsistencyError();
		
		entry.head = head;
		prev.flink = entry;
		head.blink = entry;
		head.count++;
	}
	
	public static void insertHeadList(JCacheEntry head, JCacheEntry entry) throws Exception {
		JCacheEntry next = null;
		
		checkEntry(head);
		
		next = head.flink;
		entry.flink = next;
		entry.blink = head;

		if (next.blink != head)
			raiseInconsistencyError();

		entry.head = head;
		next.blink = entry;
		head.flink = entry;
		head.count++;
	}
	
	public static JCacheEntry removeTailList(JCacheEntry head) throws Exception {
		JCacheEntry entry = null;
		JCacheEntry prev = null;
		
		entry = head.blink;
		checkEntry(head);
		prev = entry.blink;
		if ((entry.flink != head) || (prev.flink != entry))
			raiseInconsistencyError();
		
		entry.head.count--;
		entry.clearListLinks();
		
		head.blink = prev;
		prev.flink = head;
		
		return entry;
	}
	
	public static boolean removeEntryList(JCacheEntry entry) throws Exception {
		JCacheEntry next = null;
		JCacheEntry prev = null;
		next = entry.flink;
		prev = entry.blink;
		
		if ((next.blink != entry) || (prev.flink != entry)) {
			raiseInconsistencyError();
		}
		
		entry.head.count--;
		entry.clearListLinks();
		
		prev.flink = next;
		next.blink = prev;
		
		return (prev == next);
	}
	
	private void clearListLinks() {
		this.flink = null;
		this.blink = null;
		this.head = null;
		this.count = -1;
	}
	
	public void dispose() {
		clearListLinks();
		this.id = null;
		this.data = null;
	}
}
