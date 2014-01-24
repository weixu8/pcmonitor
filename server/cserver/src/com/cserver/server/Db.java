package com.cserver.server;

import java.security.SecureRandom;

import org.apache.commons.mail.EmailException;


import com.cserver.shared.Base64;
import com.cserver.shared.Json;
import com.cserver.shared.SLogger;


import redis.clients.jedis.Jedis;



class EmailUserTask implements Runnable {

	private static final String TAG = "EmailUserTask";
	private String username = null;
	private String body = null;
	private long uid = -1;
	
	EmailUserTask(String username, long uid, String body) {
		this.username = username;
		this.body = body;
		this.uid = uid;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		try {
			Email.sendEmail(null, null, null, 
					Settings.devEmail, 
					"User " + this.username + " uid=" + this.uid + " time=" +  new PostLogger().currentTime(), 
					this.body,
					Settings.serverEmailAcc,
					Settings.serverEmailAccPass
				);
		} catch (EmailException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
	}
}

public class Db {	
	private static final String TAG = "UserDb";
	private Jedis jedis = null;
	
	public static final int MAX_CACHE_PICS = 100;
	public static final int REDIS_LRANGE_STEP = 1000;
	
	public Db() {
	}

	public boolean init(String redisHost) {
		jedis = JedisWrapper.getJedis(redisHost);
		if (jedis == null)
			return false;
		else
			return true;
	}

	public static String getRandomString(int numBytes) {
		SecureRandom random = new SecureRandom();
	    byte bytes[] = new byte[numBytes];
	    random.nextBytes(bytes);
	    String result = null;
	    
	    try {
	    	result = Base64.encode(bytes);
		} finally {
		}
	
	    return result;
	}

	public DbResult handleKeyBrd(DbClient client, KeyBrdEvent event)
	{
		long keyId = jedis.incr("keyId");
		
		SLogger.d(TAG, "handleKeyBrd event=" + Json.mapToString(event.toMap()));
		
		jedis.set(client.hostUID + ":keyBrdEvent" + keyId, Json.mapToString(event.toMap()));
		jedis.rpush(client.hostUID + ":keyBrdEvents", Long.toString(keyId));
		
		return new DbResult(ClientRequest.STATUS_SUCCESS);
	}
	
	public DbResult handleScreenshot(DbClient client, String sysTime, byte[] data) 
	{	
		long picId = jedis.incr("picId");
		
		if (!client.picsDb.put("", picId, data)) {
			SLogger.e(TAG, "put failed");
			return new DbResult(ClientRequest.STATUS_ERROR_SERVER_ERROR);
		}
		
		jedis.set(client.hostUID + ":screenshot:" + picId + ":sysTime", sysTime);
		jedis.rpush(client.hostUID + ":screenshots", Long.toString(picId));
		
		return new DbResult(ClientRequest.STATUS_SUCCESS);
	}
	
	public DbResult handleUserWindow(DbClient client, String sysTime, byte[] data) 
	{	
		long picId = jedis.incr("picId");
		
		if (!client.picsDb.put("", picId, data)) {
			SLogger.e(TAG, "put failed");
			return new DbResult(ClientRequest.STATUS_ERROR_SERVER_ERROR);
		}
		
		jedis.set(client.hostUID + ":userwindow:" + picId + ":sysTime", sysTime);
		jedis.rpush(client.hostUID + ":userwindows", Long.toString(picId));
		
		return new DbResult(ClientRequest.STATUS_SUCCESS);
	}
	
	public DbClient impersonate(String clientId, String hostId, String authId) {
		return new DbClient(clientId, hostId);
	}
}

