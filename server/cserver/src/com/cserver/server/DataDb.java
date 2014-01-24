package com.cserver.server;

import java.io.File;
import java.util.HashMap;
import java.util.Map;


import com.cserver.shared.FileLock;
import com.cserver.shared.FileOps;
import com.cserver.shared.SLogger;

public class DataDb {

	private static final String TAG = "DataDb";
	private File dbPath = null;
	private int numCachedObjs = 100;
	private static volatile Map<String, DataDb> instanceMap = new HashMap<String, DataDb>();
	private JCache cache = null;
	private int cacheDataLengthLimit = 0;
	private String fileExt = "";
	
	public DataDb(File dbPath, int numCachedObjs, int cacheDataLengthLimit, String fileExt) {
		this.dbPath = dbPath;
		this.numCachedObjs = numCachedObjs;
		this.cache = new JCache(this.numCachedObjs);
		
		if (fileExt != null && !fileExt.isEmpty())
			this.fileExt = fileExt;
		
		if (!dbPath.exists())
			dbPath.mkdir();
		
		//SLogger.d(TAG, "dbPath=" + dbPath.getAbsolutePath());
		
		this.cacheDataLengthLimit = cacheDataLengthLimit;
	}
	
	public static DataDb getInstance(File dbPath, int numCachedObjs, int cacheDataLengthLimit, String fileExt) {
		DataDb db = null;
		synchronized(DataDb.class) {
			db = instanceMap.get(dbPath.getAbsolutePath());
			if (db == null) {
				db = new DataDb(dbPath, numCachedObjs, cacheDataLengthLimit, fileExt);
			}
		}
		return db;
	}
	
	private File getDbDir() {
		if (!dbPath.exists()) {
			dbPath.mkdir();
		}
		
		return dbPath;
	}

	private String makeUUID(String uid, long id) {
		return "obj_" + uid + "_" + Long.toHexString(id);
	}
	
	public boolean put(String uid, long id, byte[] data) {	
		String uuid = makeUUID(uid, id);
		
		File dataFile = getObjectFile(uuid);
		boolean result = false;
		
		FileLock flock = FileLock.getFileLock(dataFile.getAbsolutePath());
		
		result = FileOps.writeFileBinary(dataFile, data);
		
		FileLock.releaseFileLock(flock);
		
		if (result && data.length <= cacheDataLengthLimit)
			cache.put(uuid, data);
		
		return result;
	}
	
	public byte[] get(String uid, long id) {
		String uuid = makeUUID(uid, id);
		byte[] result = null;
		
		result = cache.lookup(uuid);
		if (result != null)
			return result;
		
		File dataFile = getObjectFile(uuid);
		
		FileLock flock = FileLock.getFileLock(dataFile.getAbsolutePath());
		
		result = FileOps.readFileBinary(dataFile);
		
		FileLock.releaseFileLock(flock);
		
		return result;

	}
	
	public File getObjectFile(String uuid) {
		return new File(getDbDir(), uuid + "_" + fileExt);
	}
	
	public void delete(String uid, long id) {
		String uuid = makeUUID(uid, id);
		cache.delete(uuid);
		
		File dataFile = getObjectFile(uuid);
	
		FileLock flock = FileLock.getFileLock(dataFile.getAbsolutePath());
		
		FileOps.deleteFileRecursive(dataFile);
		
		FileLock.releaseFileLock(flock);		
	}
}
