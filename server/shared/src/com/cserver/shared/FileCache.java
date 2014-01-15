package com.cserver.shared;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.cserver.shared.SLogger;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;


class FileCacheClearTask extends TimerTask {
	private static final String TAG = "FileCacheClearTask";
	private FileCache cache = null;
	
	FileCacheClearTask(FileCache cache) {
		this.cache = cache;
	}
	@Override
	public void run() {
		// TODO Auto-generated method stub
		SLogger.i(TAG, "task running");
		cache.clear();
		SLogger.i(TAG, "task completed");
	}
}

public class FileCache {
	private static final String TAG = "FileCache";
	private File cachePathFile = null;
	private Gson gson = null;
	private Timer timer = null;
	private FileCacheClearTask clearTask = null;
	private long clearTaskDeltaTime = 3*60*1000;
	private long clearTaskFileOldTime = 3600*1000;
	
	public FileCache(String cachePath) {
		cachePathFile = new File(cachePath);
		if (!cachePathFile.exists())
			cachePathFile.mkdir();
		gson = new Gson();
		timer = new Timer();
		
		clearTask = new FileCacheClearTask(this);
		timer.schedule(clearTask, clearTaskDeltaTime, clearTaskDeltaTime);
	}

	public String md5(String s) {
	    try {
	        // Create MD5 Hash
	        MessageDigest digest = java.security.MessageDigest
	                .getInstance("MD5", BouncyCastleProvider.PROVIDER_NAME);
	        digest.update(s.getBytes());
	        byte messageDigest[] = digest.digest();

	        // Create Hex String
	        StringBuffer hexString = new StringBuffer();
	        for (int i = 0; i < messageDigest.length; i++) {
	            String h = Integer.toHexString(0xFF & messageDigest[i]);
	            while (h.length() < 2)
	                h = "0" + h;
	            hexString.append(h);
	        }
	        return hexString.toString();

	    } catch (NoSuchAlgorithmException e) {
	    	SLogger.exception(TAG, e);
	    } catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
	    	SLogger.exception(TAG, e);
		}
	    return null;
	}
	
	
	File getFileDir(String resourceId) {
		String urlSum = md5(resourceId);
		if (urlSum == null) {
			SLogger.e(TAG, "md5 returns null for " + resourceId);
			return null;
		}
		
		File firstLevelDirFile = new File(cachePathFile, urlSum.substring(0, 2));
		if (!firstLevelDirFile.exists())
			firstLevelDirFile.mkdir();
		File secondLevelDirFile = new File(firstLevelDirFile, urlSum.substring(2, 4));
		if (!secondLevelDirFile.exists())
			secondLevelDirFile.mkdir();
		File thirdLevelDirFile = new File(secondLevelDirFile, urlSum.substring(4));
		if (!thirdLevelDirFile.exists())
			thirdLevelDirFile.mkdir();
		
		return thirdLevelDirFile;
	}
	
	private File getFileMap(String resourceId) {
		File fileDir = getFileDir(resourceId);
		if (fileDir == null)
			return null;
		return new File(fileDir, "map.txt");
	}
	
	public String getContentId(String resourceId) {
		if (getFile(resourceId) != null)
			return resourceId;
		return null;
	}
	
	public File getFile(String resourceId) {
		
		File fileDir = getFileDir(resourceId);
		if (fileDir == null)
			return null;
		
		File mapFile = getFileMap(resourceId);
		if (!mapFile.exists())
			return null;

		String mapContent = null;
		FileLock fileLock = FileLock.getFileLock(mapFile.getAbsolutePath());
		
		fileLock.readLock.lock();
		try {
			mapContent = FileOps.readFile(mapFile);
		} finally {
			fileLock.readLock.unlock();
		}
		
		FileLock.releaseFileLock(fileLock);
		if (mapContent == null) {
			SLogger.e(TAG, "mapContent empty");
			return null;
		}
		
        Map<String, String> map = gson.fromJson(mapContent, new TypeToken<Map<String, String>>(){}.getType());
        String filePath = map.get(resourceId);
        if (filePath == null)
        	return null;
        
        File file = new File(fileDir, filePath);
        if (!file.exists()) {
        	SLogger.e(TAG, "file is not exists " + file.getAbsolutePath());
        	return null;
        }
        
		return file;
	}
		
	public BufferedOutputStream getOutputStreamByResourceId(String resourceId) {
		File fileDir = getFileDir(resourceId);
		if (fileDir == null) {
			SLogger.e(TAG, "fileDir=null");
			return null;
		}
		
		File mapFile = getFileMap(resourceId);
		File file = null;

		FileLock fileLock = FileLock.getFileLock(mapFile.getAbsolutePath());
		fileLock.writeLock.lock();
		try {
			String filePath = null;
			//SLogger.d(TAG, "check map");
			if (!mapFile.exists()) {
				//SLogger.d(TAG, "map not exists");
				Map<String, String> map = new HashMap<String, String>();
				//SLogger.d(TAG, "map=" + mapJson);
				FileOps.writeFile(mapFile, gson.toJson(map));
				//SLogger.d(TAG, "write map");
			}
			//SLogger.d(TAG, "read map");
			String mapContent = FileOps.readFile(mapFile);
			//SLogger.d(TAG, "mapContent=" + mapContent);
	        Map<String, String> map = gson.fromJson(mapContent, new TypeToken<Map<String, String>>(){}.getType());
	        if ((filePath = map.get(resourceId)) == null) {
	        	filePath = UUID.randomUUID().toString();
	        	map.put(resourceId, filePath);
	        } 
	        FileOps.writeFile(mapFile, gson.toJson(map));
			file = new File(fileDir, filePath);
		} catch (Exception e) {
	    	SLogger.exception(TAG, e);
		} finally {
			fileLock.writeLock.unlock();
		}
		
		if (file == null) {
			SLogger.e(TAG, "file=null");
			return null;
		}
		
		FileOutputStream fos = null;		
		try {
			fos = new FileOutputStream(file);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (fos == null) {
			SLogger.e(TAG, "fos=null");
			return null;
		}
		
		return new BufferedOutputStream(fos);
	}
	
	private void clearDirByLevel(File dir, int level) {
		if (level >= 4) {
			File mapFile = new File(dir, "map.txt");
			
			FileLock fileLock = FileLock.getFileLock(mapFile.getAbsolutePath());
			fileLock.writeLock.lock();
			try {
				if (mapFile.exists()) {
					SLogger.i(TAG, "found map file here " + mapFile.getAbsolutePath());
					
					String mapContent = FileOps.readFile(mapFile);
			        Map<String, String> map = gson.fromJson(mapContent, new TypeToken<Map<String, String>>(){}.getType());
			        List<String> keys2Delete = new ArrayList<String>();
			        for (String key: map.keySet()) {
			        	
			        	File file = new File(dir, map.get(key));
			        	long lastModified = file.lastModified();
			        	long current = System.currentTimeMillis();
			        	//SLogger.i(TAG, "current=" + current + " lastModified=" + lastModified + " file=" + file.getAbsolutePath());
			        	
			        	if ((current > lastModified) && ((current - lastModified) > clearTaskFileOldTime)) {
			        		SLogger.i(TAG, "file=" + file.getAbsolutePath() + " selected for delete");
			        		keys2Delete.add(key);
			        	}
			        }
			        
			        for (String key : keys2Delete) {
			        	String value = map.get(key);
			        	File file = new File(dir, value);
			        	if (file.exists()) {
			        		FileOps.deleteFileRecursive(file);
			        	}
			        	map.remove(key);
			        }
			        if (map.size() == 0) {
			        	FileOps.deleteFileRecursive(dir);
			        } else {
			        	FileOps.writeFile(mapFile, gson.toJson(map));
			        	
			        }
				} else {
					SLogger.i(TAG, "map file not found will delete dir=" + dir.getAbsolutePath());
					FileOps.deleteFileRecursive(dir);
				}
			} catch (Exception e) {
				SLogger.exception(TAG, e);
			} finally {
				fileLock.writeLock.unlock();
			}
		} else {
			File [] childs = dir.listFiles();
			for (int i = 0; i < childs.length; i++) {
				File child = childs[i];
				if (child.exists() && child.isDirectory())
					clearDirByLevel(child, level+1);
			}
		}
	}
	
	public void clear() {
		clearDirByLevel(cachePathFile, 1);
	}
}
