package com.cserver.shared;

import java.io.File;

public class DbClient {
	private static final String TAG = "DbClient";
	public String clientId = null;
	public String hostId = null;
	public DataDb picsDb = null;
	public File clientPath = null;
	public File hostPath = null;
	public String hostUID = null;
	
	public DbClient(String dbRoot, String clientId, String hostId) {
		this.clientId = clientId;
		this.hostId = hostId;
		
		//SLogger.d(TAG, "server path=" + CServer.getInstance().path);
		
		clientPath = new File(dbRoot, "client_" + this.clientId);
		if (!clientPath.exists())
			clientPath.mkdir();
		
		hostPath = new File(clientPath, "host_" + this.hostId);
		if (!hostPath.exists())
			hostPath.mkdir();
		
		picsDb = DataDb.getInstance(new File(hostPath, "pics"), 5, 200000, ".jpg");
		hostUID = "client:" + clientId + ":host:" + hostId;
		
	}
}
