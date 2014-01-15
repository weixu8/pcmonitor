package com.cserver.shared;

public interface IClientKeyStore extends IKeyResolver {
	long createClient();
	void deleteClient(long clientId);
	IClientKey getClient(long clientId);
	long getCurrentClient();
	boolean setCurrentClient(long clientId);
	boolean setClientRemoteId(long clientId, long remoteId);
	boolean setClientSessionKey(long clientId, String sessionKey);
}
