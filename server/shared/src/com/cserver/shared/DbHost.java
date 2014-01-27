package com.cserver.shared;

import java.io.File;

public class DbHost {
	public File hostPath = null;
	public String relHostPath = null;
	public String clientId = null;
	public DataDb picsDb = null;
	public String hostId = null;
	
	public static String getRelativeClientPath(String clientId) {
		return new File("client_" + clientId).getPath();
	}
	
	public static String getRelativeHostPath(String clientId, String hostId) {
		return new File(getRelativeClientPath(clientId), "host_" + hostId).getPath();
	}
	
	public DbHost(Db db, String clientId, String hostId) {
		this.clientId = clientId;
		this.hostId = hostId;
		
		
		File clientPath = new File(db.getDbPath(), getRelativeClientPath(this.clientId));
		if (!clientPath.exists())
			clientPath.mkdir();
		
		hostPath = new File(db.getDbPath(), getRelativeHostPath(this.clientId, this.hostId));
		if (!hostPath.exists())
			hostPath.mkdir();
		
		picsDb = DataDb.getInstance(new File(hostPath, "pics"), 5, 200000, ".jpg");
	}
}
