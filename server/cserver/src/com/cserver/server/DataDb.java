package com.cserver.server;

import java.io.File;
import java.util.HashMap;
import java.util.Map;


import com.cserver.shared.FileLock;
import com.cserver.shared.FileOps;

public class DataDb {

	private static final String TAG = "DataDb";
	private File dbPath = null;
	private int numCachedObjs = 100;
	private String dbPrefix = null;
	private static volatile Map<String, DataDb> instanceMap = new HashMap<String, DataDb>();
	private JCache cache = null;
	public static final int MAX_DATA_LENGTH_TO_CACHE = 512;
	
	public DataDb(File dbPath, String dbPrefix, int numCachedObjs) {
		this.dbPath = dbPath;
		this.numCachedObjs = numCachedObjs;
		this.dbPrefix = dbPrefix;
		this.cache = new JCache(this.numCachedObjs);
	}
	
	public static DataDb getInstance(File dbPath, String dbPrefix, int numCachedObjs) {
		DataDb db = null;
		synchronized(DataDb.class) {
			db = instanceMap.get(dbPrefix);
			if (db == null) {
				db = new DataDb(dbPath, dbPrefix, numCachedObjs);
			}
		}
		return db;
	}
	
	private File getDbDir() {
		File dbDir = new File(dbPath, dbPrefix);
		if (!dbDir.exists()) {
			dbDir.mkdir();
		}
		
		return dbDir;
	}

	private String makeUUID(long uid, long id) {
		return "dbo_" + Long.toHexString(uid) + "_" + Long.toHexString(id);
	}
	
	public boolean put(long uid, long id, byte[] data) {	
		String uuid = makeUUID(uid, id);
		
		File dataFile = new File(getDbDir(), uuid);
		boolean result = false;
		
		FileLock flock = FileLock.getFileLock(dataFile.getAbsolutePath());
		
		result = FileOps.writeFileBinary(dataFile, data);
		
		FileLock.releaseFileLock(flock);
		
		if (result && data.length < MAX_DATA_LENGTH_TO_CACHE)
			cache.put(uuid, data);
		
		return result;
	}
	
	public byte[] get(long uid, long id) {
		String uuid = makeUUID(uid, id);
		byte[] result = null;
		
		result = cache.lookup(uuid);
		if (result != null)
			return result;
		
		File dataFile = new File(getDbDir(), uuid);
		
		FileLock flock = FileLock.getFileLock(dataFile.getAbsolutePath());
		
		result = FileOps.readFileBinary(dataFile);
		
		FileLock.releaseFileLock(flock);
		
		return result;

	}
	
	public void delete(long uid, long id) {
		String uuid = makeUUID(uid, id);
		cache.delete(uuid);
		
		File dataFile = new File(getDbDir(), uuid);
	
		FileLock flock = FileLock.getFileLock(dataFile.getAbsolutePath());
		
		FileOps.deleteFileRecursive(dataFile);
		
		FileLock.releaseFileLock(flock);		
	}
}
