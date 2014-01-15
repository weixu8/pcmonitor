package com.cserver.server;

import java.io.File;
import java.util.UUID;
import com.cserver.shared.FileOps;

public class ExportData {

	public static boolean putById(String data, String dataId) {
		File dataDir = new File(CServer.getInstance().path, "data");
		if (!dataDir.exists()) {
			dataDir.mkdir();
		}
		File dataFile = new File(dataDir, dataId);
		if (dataFile.exists())
			return false;
		
		FileOps.writeFile(dataFile, data);
		return true;
	}
	
	public static String put(String data) {
		String dataId = UUID.randomUUID().toString();
		if (!putById(data, dataId))
			return null;
		else
			return dataId;
	}
	
	public static String get(String dataId) {
		File dataDir = new File(CServer.getInstance().path, "data");
		if (!dataDir.exists()) {
			return null;
		}
		
		File dataFile = new File(dataDir, dataId);
		if (!dataFile.exists())
			return null;
		
		return FileOps.readFile(dataFile);
	}
}
