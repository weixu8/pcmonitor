package com.cserver.shared;

import java.io.File;

public class DbClient {
	private static final String TAG = "DbClient";
	public String clientId = null;
	public String hostId = null;
	public String uidS = null;
	public DataDb picsDb = null;
	public File clientPath = null;
	public File hostPath = null;
	
	public DbClient(String dbRoot, String clientId, String uidS, String hostId) {
		this.clientId = clientId;
		this.hostId = uidS + "-" + hostId;
		this.uidS = uidS;
		
		//SLogger.d(TAG, "server path=" + CServer.getInstance().path);
		
		clientPath = new File(dbRoot, "client_" + this.clientId);
		if (!clientPath.exists())
			clientPath.mkdir();
		
		hostPath = new File(clientPath, "host_" + this.hostId);
		if (!hostPath.exists())
			hostPath.mkdir();
		
		picsDb = DataDb.getInstance(new File(hostPath, "pics"), 5, 200000, ".jpg");
		
	}
}
