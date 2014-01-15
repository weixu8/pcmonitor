package com.cserver.shared;

public interface IConnectionEnv {
	public String getSession();
	public void setSession(String session);
	public String getServerHost();
	public int getServerPort();
	public boolean isSSL();
	public String getKsPath();
	public String getKsPass();
}
