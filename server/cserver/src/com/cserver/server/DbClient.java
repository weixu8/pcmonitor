package com.cserver.server;

import java.io.File;

import com.cserver.shared.SLogger;

public class DbClient {
	private static final String TAG = "DbClient";
	public String clientId = null;
	public String hostId = null;
	public DataDb picsDb = null;
	public File clientPath = null;
	public File hostPath = null;
	public String hostUID = null;
	
	public DbClient(String clientId, String hostId) {
		this.clientId = clientId;
		this.hostId = hostId;
		
		//SLogger.d(TAG, "server path=" + CServer.getInstance().path);
		
		clientPath = new File(CServer.getInstance().path, "client_" + this.clientId);
		if (!clientPath.exists())
			clientPath.mkdir();
		
		hostPath = new File(clientPath, "host_" + this.hostId);
		if (!hostPath.exists())
			hostPath.mkdir();
		
		picsDb = DataDb.getInstance(new File(hostPath, "pics"), 5, 200000, ".jpg");
		hostUID = "client:" + clientId + ":host:" + hostId;
		
	}
}
