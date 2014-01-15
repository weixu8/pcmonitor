package com.cserver.server;

import java.io.File;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

import nl.captcha.Captcha;

import org.apache.commons.mail.EmailException;


import com.cserver.shared.BCrypt;
import com.cserver.shared.Base64;
import com.cserver.shared.Base64DecoderException;
import com.cserver.shared.DataCrypt;
import com.cserver.shared.FileOps;
import com.cserver.shared.Json;
import com.cserver.shared.LastError;
import com.cserver.shared.Message;
import com.cserver.shared.MessageCrypt;
import com.cserver.shared.MessageInfo;
import com.cserver.shared.SLogger;
import com.cserver.shared.Errors;
import com.cserver.shared.SPurchase;
import com.cserver.shared.SRequest;
import com.cserver.shared.UserDataValidator;
import com.cserver.shared.UserInfo;
import com.cserver.shared.WaitableCompletionTask;
import com.cserver.shared.KeyQuery;
import com.cserver.shared.CaptchaResult;

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
	
	private DataDb msgDb = null;
	private DataDb keysDb = null;
	private DataDb picsDb = null;
	
	public static final int CAPTCHA_EXPIRE_SECONDS = 600;
	public static final int CLIENT_EXPIRE_SECONDS = 600;
	
	public static final int CAPTCHA_WIDTH = 400;
	public static final int CAPTCHA_HEIGHT = 200;
	
	public static final int MAX_KEYS = 1000;
	
	public static final int MAX_CACHE_MESSAGES = 100*100;
	public static final int MAX_CACHE_KEYS = 100*100;
	public static final int MAX_CACHE_PICS = 100*100;
	
	public static final int MSG_TTL_MILLIS = 7*24*3600*1000;//7 days;
	public static final int KEY_TTL_MILLIS = 7*24*3600*1000;//7 days;
	
	public static final int KEYS_EXPIRE_TASK_TIMEOUT_MILLIS = 3600*1000;//1 hour
	public static final int INVITE_TTL_SECONDS = 7*24*3600;//1 day
	
	public static final int REDIS_LRANGE_STEP = 1000;
	
	public Db() {
		msgDb = DataDb.getInstance(new File(CServer.getInstance().path), "userMessages", MAX_CACHE_MESSAGES);
		keysDb = DataDb.getInstance(new File(CServer.getInstance().path), "userKeys", MAX_CACHE_KEYS);
		picsDb = DataDb.getInstance(new File(CServer.getInstance().path), "userPics", MAX_CACHE_PICS);
	}

	public boolean init(String redisHost) {
		jedis = JedisWrapper.getJedis(redisHost);
		if (jedis == null)
			return false;
		else
			return true;
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
	
	public DbResult userAuthByNameAndPassWithCaptcha(String uidS, String username, String password, String captchaId, String captchaAnswer,
			int captchaOp) {
		if ((captchaId == null) || (captchaAnswer == null)) {
			return new DbResult(Errors.INVALID_REQUEST_PARAMETERS);
		}	
		
		int error = verifyCaptcha(captchaId, captchaAnswer, uidS, captchaOp);
		if (error != Errors.SUCCESS) {
			return new DbResult(error);
		}
		return userAuthByNameAndPass(username, password);
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
		if (CServer.isDebug())
			SLogger.i(TAG, "userSessionDelete=" + sname);
		
		String sessionIdS = jedis.get("sname:"+ sname);
		if (sessionIdS == null) 
			return;
		userSessionDeleteById(sessionIdS);
	}
	
	private void userSessionDeleteById(String sessionIdS) {	
		if (CServer.isDebug())
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
	
	public String getCurrentDate() {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US); 	
		Calendar cal = Calendar.getInstance();
		cal.setTime(new Date());
		
		return sdf.format(cal.getTime());
	}
	
	public int userAccountRegister(String username, String password) {
		SLogger.i(TAG, "userAccountRegister username=" + username);
		
		if ((username == null) || (null != UserDataValidator.validateLogin(username)))
			return Errors.INVALID_REQUEST_PARAMETERS;
		
		if ((password == null) || (null != UserDataValidator.validatePass(password)))
			return Errors.INVALID_REQUEST_PARAMETERS;
		
		if (jedis.get("username:" + username + ":uid") != null) {
			SLogger.i(TAG, "username=" + username + " already exists");
			return Errors.ACCOUNT_ALREADY_REGISTRED;
		}
		
		long uid = getNewUserId();
		String uidS = Long.toString(uid);
		if (jedis.setnx("username:" + username + ":uid", uidS) == 0) {
			SLogger.i(TAG, "userid=" + uid + " already exists");
			return Errors.ACCOUNT_ALREADY_REGISTRED;
		}
		
		String hashed = BCrypt.hashpw(password, BCrypt.gensalt(Settings.pwdSaltRounds));
		
		jedis.set("uid:"+ uidS + ":password", hashed);
		jedis.set("uid:"+ uidS + ":username", username);
		jedis.set("uid:"+ uidS + ":ioreqs", "0");
		jedis.set("uid:"+ uidS + ":date", getCurrentDate());		
		jedis.set("uid:"+ uidS + ":admob", Integer.toString(1));	
		jedis.set("uid:" + uidS + ":accessTime", "0");
		jedis.set("uid:" + uidS + ":age", "-1");
		jedis.set("uid:" + uidS + ":gender", "-1");
		jedis.set("uid:" + uidS + ":picId", "-1");
		
		jedis.rpush("users", uidS);
		jedis.rpush("usernames", username);
		
		CServer.getInstance().execService.submit(new EmailUserTask(username, uid, " Registred"));
		SLogger.i(TAG, "userAccountRegister username=" + username + " success");
		
		String sname = createSessionForUser(uidS);
		if (sname == null) {
			SLogger.i(TAG, "session creation failure");
			return Errors.INTERNAL_SERVER_ERROR;
		}
		
		jedis.set("uid:" + uidS + ":active", "1");
		
		return Errors.SUCCESS;
	}
			
	private String getCaptchaAnswerById(String captchaId) {
		return jedis.get("captcha:" + captchaId + ":answer");
	}
	
	private String getCaptchaOwnerById(String captchaId) {
		return jedis.get("captcha:" + captchaId + ":owner");
	}
	
	private int getCaptchaOpById(String captchaId) {
		String opS = jedis.get("captcha:" + captchaId + ":operation");
		if (opS == null)
			return -1;
		return Integer.parseInt(opS);
	}
	
	private int verifyCaptcha(String captchaId, String captchaAnswer, String uidS, int captchaOp) {	
		if (captchaId == null || captchaAnswer == null)
			return Errors.INVALID_REQUEST_PARAMETERS;
		
		if (getCaptchaOpById(captchaId) != captchaOp) {
			SLogger.e(TAG, "invalid captchaId=" + captchaId);
			return Errors.CAPTCHA_NOT_FOUND;
		}
		
		String captchaOwner = getCaptchaOwnerById(captchaId);
		if (uidS == null) {
			if (captchaOwner != null) {
				SLogger.e(TAG, "invalid captchaId=" + captchaId + " captchaOwner=" + captchaOwner);
				return Errors.CAPTCHA_OWNER_INVALID;
			}
		} else {
			if ((captchaOwner != null) && !captchaOwner.equals(uidS)) {
				SLogger.e(TAG, "invalid captchaId=" + captchaId + " captchaOwner=" + captchaOwner 
						+ " uidS=" + uidS);
				return Errors.CAPTCHA_OWNER_INVALID;
			}
		}
		
		String cAnswer = getCaptchaAnswerById(captchaId);
		if ((cAnswer == null) || (captchaAnswer == null) || !cAnswer.equals(captchaAnswer)) {
			SLogger.e(TAG, "invalid captchaAnswer");
			return Errors.CAPTCHA_ANSWER_INVALID;
		}
		
		return Errors.SUCCESS;
	}
	
	private void setUserPic(long uid, byte[] picBytes) {
		long picId = jedis.incr("picId");
		picsDb.put(uid, picId, picBytes);
		jedis.set("uid:" + uid + ":picId", Long.toString(picId));
	}
	
	private void deleteUserPic(long uid) {
		String picIdS = JedisWrapper.keyGetDelete(jedis, "uid:" + uid + ":picId");
		if (picIdS != null) {
			long picId = Long.parseLong(picIdS);
			if (picId >= 0) {
				picsDb.delete(uid, picId);
			}
		}
	}
	
	public int userAccountDelete(DbUser user, String username, String password, 
			String captchaId, String captchaAnswer) {
		
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
		
		int error = verifyCaptcha(captchaId, captchaAnswer, uidS, SRequest.CAPTCHA_OP_DELETE);
		if (error != Errors.SUCCESS) {
			SLogger.e(TAG, "verifyCaptcha err=" + error);
			return error;
		}
		
		long uid = Long.parseLong(uidS);
		
		jedis.set("uid:" + uidS + ":active", "0");
		
		jedis.lrem("users", 0, uidS);
		jedis.lrem("usernames", 0, usernameS);
		userSessionDeleteById(sessionIdS);
		
		deleteUserKeys(user, true);
		deleteUserMessages(user);
		deleteUserPurchases(user);
		
		jedis.del("uid:"+ uidS + ":username");
		jedis.del("uid:"+ uidS + ":session"); 
		jedis.del("uid:"+ uidS + ":password"); 
		jedis.del("uid:"+ uidS + ":ioreqs");
		jedis.del("uid:"+ uidS + ":date");
		jedis.del("uid:"+ uidS + ":admob");
		jedis.del("uid:" + uidS + ":accessTime");
		jedis.del("uid:" + uidS + ":currPublicKeyId");

		
		deleteFromAllFriends(uid);
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
		
		deleteUserPic(uid);
		
		jedis.del("username:" + usernameS + ":uid");
		
		CServer.getInstance().execService.submit(new EmailUserTask(username, uid, " Deleted"));
		
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

	public int purchaseDataVerify(DbUser user, String data,
			String signature) {
		
		if (Security.verifyPurchase(CServer.getInstance().base64EncodedAppPublicKey, data, signature)) {
			SLogger.i(TAG, "purchaseDataVerify:success");
			return Errors.SUCCESS;
		} else {
			SLogger.i(TAG, "purchaseDataVerify:failed");
			return Errors.PURCHASE_DATA_SIGN_VERIFICATION_FAILED;
		}
	}

	
	private String purchaseFind(String session, String pname) {
		String uidS = userBySession(session);
		if (uidS == null) {
			SLogger.i(TAG, "session=" + session + " is invalid");
			return null;
		}
		
		String pId = jedis.get("pname:" + pname);;
		if (pId == null){
			SLogger.i(TAG, "pname=" + pname + " is invalid");
			return null;
		}
		
		String puidS = jedis.get("purchase:" + pId + ":uid"); 		
		if ((puidS == null) || !puidS.equals(uidS)) {
			SLogger.e(TAG, "purchase not found puidS=" + puidS + " uidS=" + uidS + " pId" + pId);
			return null;
		}
		
		if (!jedis.sismember("uid:"+ uidS + ":purchases", pId)) {
			SLogger.e(TAG, "purchase not found uidS=" + uidS + " pId=" + pId);
			return null;
		}	
		
		return pId;
	}
	
	public int purchaseVerify(DbUser user, String pname) {
		
		SLogger.i(TAG, "purchaseVerify:session=" + user.session + " pname=" + pname);
		String pId = purchaseFind(user.session, pname);
		if (pId == null) {
			SLogger.e(TAG, "purchase not found by session=" + user.session + " pname=" + pname);
			return Errors.PURCHASE_NOT_FOUND;
		}
		
		return Errors.SUCCESS;
	}
	
	public int purchaseFinished(DbUser user, String pname, String pinfo) {
		SLogger.i(TAG, "purchaseFinished:session=" + user.session + " pname=" + pname + " pinfo=" + pinfo);

		String pId = purchaseFind(user.session, pname);
		if (pId == null) {
			SLogger.e(TAG, "purchase not found by session=" + user.session + " pname=" + pname);
			return Errors.PURCHASE_NOT_FOUND;
		}
		
		boolean finished = false;
		
		String uidS = jedis.get("purchase:" + pId + ":uid");
		String sku = jedis.get("purchase:" + pId + ":sku");
		if (uidS == null || sku == null) {
			SLogger.e(TAG, "Not found sku=" + sku + " uidS=" + uidS + " in pId=" + pId);
			return Errors.INTERNAL_SERVER_ERROR;
		}
		
		if (sku.equals(SPurchase.SKU_REMOVE_ADMOB)) {
			jedis.set("uid:"+ uidS + ":admob", Integer.toString(0));
			finished = true;
		} else if (sku.equals(SPurchase.SKU_ADD_1000_REQUESTS)) {
			//nothing
			finished = true;
		} else {
			SLogger.e(TAG, "unknown sku=" + sku);
			finished = false;
		}
		
		if (finished) {
			jedis.set("purchase:" + pId + ":finishedPurchaseInfo", pinfo);
			jedis.set("purchase:" + pId + ":finished", Integer.toString(1));
			jedis.set("purchase:" + pId + ":finishedDate", getCurrentDate());
			return Errors.SUCCESS;
		}
		
		return Errors.PURCHASE_NOT_FOUND;
	}
	
	public int purchaseConsumed(DbUser user, String pname, String pinfo) {
		
		SLogger.i(TAG, "purchaseConsumed:session=" + user.session + " pname=" + pname + " pinfo=" + pinfo);

		boolean consumed = false;
		String pId = purchaseFind(user.session, pname);
		if (pId == null)
			return Errors.PURCHASE_NOT_FOUND;
		
		
		String uidS = jedis.get("purchase:" + pId + ":uid");
		String sku = jedis.get("purchase:" + pId + ":sku");
		if (uidS == null || sku == null) {
			SLogger.e(TAG, "Not found sku=" + sku + " uidS=" + uidS + " in pId=" + pId);
			return Errors.INTERNAL_SERVER_ERROR;
		}
	
		if (sku.equals(SPurchase.SKU_ADD_1000_REQUESTS)) {
			jedis.incrBy("uid:"+ uidS + ":ioreqs", 1000);
			consumed = true;
		} else {
			consumed = false;
		}
		
		if (consumed) {
			jedis.set("purchase:" + pId + ":consumedPurchaseInfo", pinfo);
			jedis.set("purchase:" + pId + ":consumed", Integer.toString(1));
			jedis.set("purchase:" + pId + ":consumedDate", getCurrentDate());
			return Errors.SUCCESS;
		}
		
		return Errors.PURCHASE_NOT_FOUND;
	}
	
	public String purchaseCreate(DbUser user, String sku) {
		SLogger.i(TAG, "purchaseCreate:session=" + user.session + " sku=" + sku);

		String pId = Long.toString(getNewPurchaseId());
		String pName = getRandomString(32);

		if (jedis.setnx("pname:" + pName, pId) == 0) {
			SLogger.e(TAG, "pname=" + pName + " already exists");
			return null;
		}
		
		jedis.set("purchase:" + pId + ":createdDate", getCurrentDate()); 
		jedis.set("purchase:" + pId + ":uid", user.uidS); 
		jedis.set("purchase:" + pId + ":sku", sku);
		jedis.set("purchase:" + pId + ":consumed", Integer.toString(0));
		jedis.set("purchase:" + pId + ":consumedDate", getCurrentDate());
		jedis.set("purchase:" + pId + ":finished", Integer.toString(0));
		jedis.set("purchase:" + pId + ":finishedDate", Integer.toString(0));
		jedis.set("purchase:" + pId + ":name", pName);
		
		jedis.sadd("uid:" + user.uidS + ":purchases", pName);
 		return pName;
	}
	
	
	private void deleteUserPurchases(DbUser user) {
		while (true) {
			String pName = jedis.lpop("uid:" + user.uidS + ":purchases");
			if (pName == null)
				break;
			
			String pId = JedisWrapper.keyGetDelete(jedis, "pname:" + pName);
			if (pId != null) {
				jedis.del("purchase:" + pId + ":createdDate"); 
				jedis.del("purchase:" + pId + ":uid"); 
				jedis.del("purchase:" + pId + ":sku");
				jedis.del("purchase:" + pId + ":consumed");
				jedis.del("purchase:" + pId + ":consumedDate");
				jedis.del("purchase:" + pId + ":finished");
				jedis.del("purchase:" + pId + ":finishedDate");
				jedis.del("purchase:" + pId + ":name");
			}
		}
		jedis.del("uid:" + user.uidS + ":purchases");
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
	
	public boolean userAccActive(long uid) {
		String activeS = jedis.get("uid:" + uid + ":active");
		if (activeS == null)
			return false;
		
		return (Long.parseLong(activeS) > 0) ? true : false;		
	}
	
	public UserInfo getUserInfoById(DbUser user, long uid, boolean bUserPic) {
		if (!userAccActive(uid))
			return null;
		
		UserInfo userInfo = new UserInfo();
		
		userInfo.accessTime = Long.parseLong(jedis.get("uid:" + uid + ":accessTime"));
		userInfo.username = jedis.get("uid:" + uid + ":username");
		userInfo.uid = uid;
		
		userInfo.age = Long.parseLong(jedis.get("uid:" + uid + ":age"));
		userInfo.gender = Long.parseLong(jedis.get("uid:" + uid + ":gender"));
		
		if (bUserPic) {
			long picId = Long.parseLong(jedis.get("uid:" + uid + ":picId"));
			if (picId >= 0) {
				userInfo.picBytes = picsDb.get(uid, picId);
			}
		}
		
		userInfo.job = jedis.get("uid:" + uid + ":job");
		userInfo.jobTitle = jedis.get("uid:" + uid + ":jobTitle");
		userInfo.school = jedis.get("uid:" + uid + ":school");
		userInfo.interests = jedis.get("uid:" + uid + ":interests");
		userInfo.hobby = jedis.get("uid:" + uid + ":hobby");
		userInfo.aboutMe = jedis.get("uid:" + uid + ":aboutMe");
		
		if (isFriend(user.uid, uid))
			userInfo.type = UserInfo.TYPE_FRIEND;
		else
			userInfo.type = UserInfo.TYPE_OTHER;
				
		KeyQuery kq = pubKeyQueryUserCurrentKey(user, uid);
		if (kq != null && kq.error == Errors.SUCCESS) {
			userInfo.key = kq.publicKey;
			userInfo.keyId = kq.keyId;
		}
		
		return userInfo;
	}
	
	public UserInfo queryProfile(DbUser user) {
		return getUserInfoById(user, user.uid, true);
	}
	
	public int updateProfile(DbUser user, UserInfo profile) {
		if (!userAccActive(user.uid))
			return Errors.ACCOUNT_INVALID;
		
		if (profile.age > 0)
			jedis.set("uid:" + user.uidS + ":age", Long.toString(profile.age));
		
		if (profile.gender > 0)
			jedis.set("uid:" + user.uidS + ":gender", Long.toString(profile.gender));
		
		if (profile.picBytes != null) {
			deleteUserPic(user.uid);
			setUserPic(user.uid, profile.picBytes);
		}
		
		if (profile.job != null)
			jedis.set("uid:" + user.uidS + ":job", profile.job);

		if (profile.jobTitle != null)
			jedis.set("uid:" + user.uidS + ":jobTitle", profile.jobTitle);
		
		if (profile.school != null)
			jedis.set("uid:" + user.uidS + ":school", profile.school);
		
		if (profile.interests != null)
			jedis.set("uid:" + user.uidS + ":interests", profile.interests);
		
		if (profile.hobby != null)
			jedis.set("uid:" + user.uidS + ":hobby", profile.hobby);
		
		if (profile.aboutMe != null)
			jedis.set("uid:" + user.uidS + ":aboutMe", profile.aboutMe);
		
		
		return Errors.SUCCESS;
	}
	
		
	public boolean isUserInfoMatch(UserInfo info, UserInfo match) {
		if (CServer.isDebug())
			SLogger.d(TAG, "isUserInfoMatch: info=" + Json.mapToString(info.toMap()) + " vs. match="
				+ Json.mapToString(match.toMap()));

		if (match.username != null)
			if (!info.username.contains(match.username))
				return false;
		
		if (match.age >= 0) {
			if (info.age < 0)
				return false;
			if (info.age < match.age)
				return false;
		}
		
		if (match.extraL >= 0) {
			if (info.age < 0)
				return false;
			if (info.age > match.extraL)
				return false;
		}
		
		if (match.gender >= 0) {
			if (info.gender < 0 && match.gender != UserInfo.GENDER_ANY)
				return false;
			
			if (match.gender != UserInfo.GENDER_ANY && match.gender != info.gender)
				return false;
		}
		
		
		if (match.interests != null) {
			if (info.interests == null)
				return false;
			
			int tagsFound = 0;
			for (String tag : match.interests.split(" ")) {
				if (info.interests.contains(tag))
					tagsFound++;
			}
			
			if (tagsFound == 0)
				return false;
		}
		
		return true;
	}
	
	public List<Long> searchUsers(DbUser user, UserInfo match) {
		// TODO Auto-generated method stub
		
		long usersCount = jedis.llen("users");
		long start = 0;
		Set<Long> idsSet = new TreeSet<Long>();
		
		do {
			List<String> uidSList = jedis.lrange("users", start, start + REDIS_LRANGE_STEP);
			start+= REDIS_LRANGE_STEP;
			if ((uidSList == null) || (uidSList.size() == 0))
				break;
			
			for (String uidS : uidSList) {
				long uid = Long.parseLong(uidS);
				if (!readAccess(user, uid))
					continue;
				
				if (uid == user.uid)//don't add yourself
					continue;
				
				UserInfo info = getUserInfoById(user, uid, false);
				if (isUserInfoMatch(info, match))
					idsSet.add(uid);
			}
		} while (start < usersCount);
		
		List<Long> idsList = new ArrayList<Long>();
		for (Long id : idsSet) {
			idsList.add(id);
		}
		
		return idsList;
	}

	public DbResult queryUserInfo(DbUser user, long uid) {
		if (!readAccess(user, uid)) {
			SLogger.e(TAG, "uid not found for uid=" + uid);
			return new DbResult(Errors.ACCESS_DENIED);
		}
		
		UserInfo userInfo = getUserInfoById(user, uid, true);	
		if (userInfo == null) {
			SLogger.d(TAG, "UserInfo not found for uid=" + uid);
			return new DbResult(Errors.INTERNAL_SERVER_ERROR);
		}
		
		DbResult result = new DbResult(Errors.SUCCESS);
		result.userInfo = userInfo;
		
		return result;
	}

	private boolean readAccess(DbUser user, long uid) {
		if (!userAccActive(uid) || !userAccActive(user.uid))
			return false;

		return true;
	}

	private boolean isFriend(long uid, long match) {
		if (!userAccActive(uid) || !userAccActive(match))
			return false;
		
		return jedis.sismember("uid:" + uid + ":friendsSet", Long.toString(match));
	}
	
	private boolean writeAccess(DbUser user, long uid) {
		
		if (!userAccActive(uid) || !userAccActive(user.uid))
			return false;

		return isFriend(uid, user.uid);		
	}
	
	public long sendMessage(DbUser user, long uid, byte[] message, long keyId) {
		// TODO Auto-generated method stub
		if (!writeAccess(user, uid)) {
			SLogger.i(TAG, "uid=" + uid + " not found");
			return -1;
		}
		
		long msgId = jedis.incr("msgid");
		if (!msgDb.put(uid, msgId, message)) {
			SLogger.e(TAG, "cant save message with id=" + msgId);
			return -1;
		}
		
		jedis.set("message:" + msgId + ":encKeyId", Long.toString(keyId));
		jedis.set("message:" + msgId + ":time", Long.toString(System.currentTimeMillis()));
		
		jedis.rpush("uid:"+ uid + ":messages", Long.toString(msgId));
		if (CServer.isDebug())
			SLogger.d(TAG, "sendMessage from=" + user.uidS + " to=" + uid + " msgId=" + msgId + " bytes=" + Base64.encode(message));
		return msgId;
	}
	
	private void deleteUserMessages(DbUser user) {
		while (true) {
			String msgIdS = jedis.lpop("uid:" + user.uidS + ":messages");
			if (msgIdS == null)
				break;
			
			long msgId = Long.parseLong(msgIdS);
			jedis.del("message:" + msgId + ":encKeyId");
			jedis.del("message:" + msgId + ":time");
			msgDb.delete(user.uid, msgId);
		}
		jedis.del("uid:" + user.uidS + ":messages");
	}
	
	public List<MessageInfo> queryMessages(DbUser user, long lastMsgId) {
		// TODO Auto-generated method stub
		
		long msgsCount = jedis.llen("uid:" + user.uidS + ":messages");
		long start = 0;
		SortedSet<Long> msgIds = new TreeSet<Long>();
		do {
			List<String> msgIdsS = jedis.lrange("uid:" + user.uidS + ":messages", start, start + REDIS_LRANGE_STEP);
			start+= REDIS_LRANGE_STEP;
			if ((msgIdsS == null) || (msgIdsS.size() == 0))
				break;
			
			for (String idS : msgIdsS) {
				long id = Long.parseLong(idS);
				if (id > lastMsgId)
					msgIds.add(id);
			}
		} while (start < msgsCount);
		
		List<MessageInfo> msgList = new ArrayList<MessageInfo>();
		for (Long msgId : msgIds) {
			
			byte[] msgBytes = msgDb.get(user.uid, msgId);	
			if (msgBytes == null) {
				SLogger.e(TAG, "cant found msgBytes by msgid=" + msgId);
			}
			
			String encKeyId = jedis.get("message:"+ msgId + ":encKeyId");
			if (encKeyId != null) {
				SLogger.e(TAG, "cant get encKeyId by msgid=" + msgId);
			}
			
			if ((encKeyId != null) && (msgBytes != null)) {
				MessageInfo msg = new MessageInfo();
				msg.bytes = msgBytes;
				msg.msgId = msgId;
				msg.encKeyId = Long.parseLong(encKeyId);
				
				msgList.add(msg);
				if (CServer.isDebug())
					SLogger.d(TAG, "query message id=" + msgId + " bytes=" + Base64.encode(msgBytes));
			}
			
			jedis.lrem("uid:" + user.uidS + ":messages", 0, Long.toString(msgId));
			jedis.del("message:" + msgId + ":encKeyId");
			jedis.del("message:" + msgId + ":time");
			msgDb.delete(user.uid, msgId);
		}
		
		return msgList;
	}
	
	private void deleteUserKeys(DbUser user, boolean all) {
		while (true) {
			long keysCount = jedis.llen("uid:" + user.uidS + ":keys");
			if (CServer.isDebug())
				SLogger.d(TAG, "keysCount=" + keysCount + " uid=" + user.uidS);
			if (keysCount == 0)
				break;
			
			if (!all && (keysCount < MAX_KEYS))
				break;
			
			String keyIdS = jedis.lpop("uid:" + user.uidS + ":keys");
			if (keyIdS != null) {
				if (CServer.isDebug())
					SLogger.d(TAG, "delete key withId=" + keyIdS + " user=" + user.uidS);
				jedis.del("key:" + keyIdS + ":owner");
				jedis.del("key:" + keyIdS + ":time");
				keysDb.delete(user.uid, Long.parseLong(keyIdS));
			} else {
				break;
			}
		}
		
		if (all)
			jedis.del("uid:" + user.uidS + ":keys");
	}
	
	public int pubKeyRegister(DbUser user, String pubKey, long keyId) {
		if (pubKey == null || keyId == -1) {
			SLogger.e(TAG, "pubKey not extracted");
			return Errors.INVALID_REQUEST_PARAMETERS;
		}
		
		byte[] pubKeyBytes = null;
		try {
			pubKeyBytes = Base64.decode(pubKey);
		} catch (Exception e) {
			SLogger.exception(TAG, e);
		}
		
		if (pubKeyBytes == null) {
			SLogger.e(TAG, "pubKey not decoded");
			return Errors.INVALID_REQUEST_PARAMETERS;
		}
		
		if (jedis.setnx("key:" + keyId + ":owner", user.uidS) == 0) {
			SLogger.e(TAG, "key " + keyId + " already exists");
			return Errors.OBJECT_ALREADY_EXISTS;
		}
		
		jedis.set("key:" + keyId + ":time", Long.toString(System.currentTimeMillis()));
		
		if (!keysDb.put(user.uid, keyId, pubKeyBytes)) {
			jedis.del("key:" + keyId + ":owner");
			jedis.del("key:" + keyId + ":time");
			SLogger.e(TAG, "cant save key=" + keyId + " in file");
			return Errors.INTERNAL_SERVER_ERROR;
		}
		
		jedis.set("uid:"+ user.uidS + ":currPublicKeyId", Long.toString(keyId));
		jedis.rpush("uid:" + user.uidS + ":keys", Long.toString(keyId));
		
		deleteUserKeys(user, false);
	
		if (CServer.isDebug())
			SLogger.d(TAG, "user=" + user.uidS + " set publicKey=" + pubKey);
		
		return Errors.SUCCESS;
	}
	
	public KeyQuery pubKeyQueryByKeyId(DbUser user, long uid, long keyId) {
		KeyQuery result = new KeyQuery();
		
		String keyOwner = jedis.get("key:" + keyId + ":owner");
		if (keyOwner == null) {
			SLogger.e(TAG, "key " + keyId + " not found");
			result.error = Errors.OBJECT_NOT_FOUND;
			return result;
		}
		
		if (!keyOwner.equals(Long.toString(uid))) {
			SLogger.e(TAG, "key " + keyId + " owner is " + keyOwner + " and isn't " + uid);
			result.error = Errors.ACCESS_DENIED;
			return result;
		}
		
		byte[] keyBytes = keysDb.get(uid, keyId);
		if (keyBytes == null) {
			SLogger.e(TAG, "Cant found value of key " + keyId);
			result.error = Errors.INTERNAL_SERVER_ERROR;
			return result;
		}
		
		result.publicKey = Base64.encode(keyBytes);
		if (result.publicKey == null) {
			SLogger.e(TAG, "Cant extract value of key " + keyId);
			result.error = Errors.INTERNAL_SERVER_ERROR;
			return result;
		}
		
		result.error = Errors.SUCCESS;
		result.keyId = keyId;
		
		return result;
	}
	
	public KeyQuery pubKeyQueryUserCurrentKey(DbUser user, long uid) {
		KeyQuery result = new KeyQuery();
		
		String keyIdS = jedis.get("uid:" + Long.toString(uid) + ":currPublicKeyId");
		if (keyIdS == null) {
			SLogger.e(TAG, "can't query current key of user " + uid);
			result.error = Errors.OBJECT_NOT_FOUND;
			return result;
		}
		long keyId = Long.parseLong(keyIdS);
		String ownerS = jedis.get("key:" + keyId + ":owner");
		if ((ownerS == null) || !ownerS.equals(Long.toString(uid))) {
			SLogger.e(TAG, "key=" + keyId + " ownerS=" + ownerS + " should be " + uid);
			result.error = Errors.ACCESS_DENIED;
			return result;
		}
		
		
		byte[] keyBytes = keysDb.get(uid, keyId);
		if (keyBytes == null) {
			SLogger.e(TAG, "Cant found value of key " + keyId);
			result.error = Errors.INTERNAL_SERVER_ERROR;
			return result;
		}
		
		result.publicKey = Base64.encode(keyBytes);
		if (result.publicKey == null) {
			SLogger.e(TAG, "can't load key " + result.keyId + " value");
			result.error = Errors.OBJECT_NOT_FOUND;
			return result;	
		}		
		result.keyId = keyId;
		result.error = Errors.SUCCESS;
		
		return result;
	}


	public int deleteUser(DbUser user, String username, String password, 
			String captchaId, String captchaAnswer) {
		// TODO Auto-generated method stub
		
		return userAccountDelete(user, username, password, captchaId, captchaAnswer);
	}
	
	private String regCaptcha(DbUser user, Captcha captcha, int captchaOp) {
		String captchaId = getRandomString(32);
		if (captchaId == null) {
			SLogger.e(TAG, "captchaId generation failed");
			return null;
		}
		
		if (!JedisWrapper.keySetNxExpire(jedis, "captcha:" + captchaId + ":answer", captcha.getAnswer(), CAPTCHA_EXPIRE_SECONDS))
			return null;
		
		if (user != null) {
			if (!JedisWrapper.keySetNxExpire(jedis, "captcha:" + captchaId + ":owner", user.uidS, CAPTCHA_EXPIRE_SECONDS))
				return null;
		}
		
		if (!JedisWrapper.keySetNxExpire(jedis, "captcha:" + captchaId + ":operation", Integer.toString(captchaOp), CAPTCHA_EXPIRE_SECONDS))
			return null;

		return captchaId;
	}
	
	private void delCaptcha(String captchaId) {
		jedis.del("captcha:" + captchaId + ":answer",
				"captcha:" + captchaId + ":owner", 
				"captcha:" + captchaId + ":operation");
	}
	
	public CaptchaResult getCaptcha(DbUser user, int captchaOp) {
		switch (captchaOp) {
		case SRequest.CAPTCHA_OP_SIGNIN:
		case SRequest.CAPTCHA_OP_DELETE:
		case SRequest.CAPTCHA_OP_PWD_CHANGE:
			break;
		default:
			SLogger.e(TAG, "invalid captchaOp=" + captchaOp);
			return new CaptchaResult(Errors.INVALID_REQUEST_PARAMETERS); 
		}
		
		// TODO Auto-generated method stub
		Captcha captcha = CaptchaGenerator.genCaptcha(CAPTCHA_WIDTH, CAPTCHA_HEIGHT);
		if (captcha == null) {
			SLogger.e(TAG, "captcha generation failed");
			return new CaptchaResult(Errors.INTERNAL_SERVER_ERROR);
		}
		
		String captchaId = regCaptcha(user, captcha, captchaOp);
		if (captchaId == null) {
			SLogger.e(TAG, "captcha regestration failed");
			return new CaptchaResult(Errors.INTERNAL_SERVER_ERROR);
		}
		
		CaptchaResult result = new CaptchaResult(Errors.SUCCESS);
		result.captchaBytes = CaptchaGenerator.captchaToBytes(captcha);
		result.captchaId = captchaId;
		
		return result;
	}

	public DbResult pwdChange(DbUser user, String username, String password,
			String newPassword, String captchaId, String captchaAnswer) {
		// TODO Auto-generated method stub
		if (!user.username.equals(username)) {
			SLogger.e(TAG, "invalid session user name vs username");
			return new DbResult(Errors.AUTH_FAILURE);
		}
		
		DbResult result = userAuthByNameAndPassWithCaptcha(user.uidS, username, password, captchaId, 
				captchaAnswer, SRequest.CAPTCHA_OP_PWD_CHANGE);
		
		if (result.error != Errors.SUCCESS) {
			SLogger.e(TAG, "userAuthByNameAndPassWithCaptcha failed with err=" + result.error);
			return result;
		}
		
		String hashed = BCrypt.hashpw(newPassword, BCrypt.gensalt(Settings.pwdSaltRounds));
		jedis.set("uid:" + result.user.uidS + ":password", hashed);
		
		return result;
	}
	
	
	public DbResult clientRegister(String clientKey, long clientKeyId) {
		long clientId = MessageCrypt.getRndLong();
		
		if (!JedisWrapper.keySetNxExpire(jedis, "client:" + clientId + ":key", clientKey, CLIENT_EXPIRE_SECONDS))
			return new DbResult(Errors.CLIENT_ENCRYPTION_SESSION_ALREADY_EXISTS);
		
		if (!JedisWrapper.keySetNxExpire(jedis, "client:" + clientId + ":keyId", Long.toString(clientKeyId), CLIENT_EXPIRE_SECONDS))
			return new DbResult(Errors.CLIENT_ENCRYPTION_SESSION_ALREADY_EXISTS);
		
		byte [] aesKey = new byte[DataCrypt.AES_KEY_LENGTH];
		SecureRandom random = new SecureRandom();
	    random.nextBytes(aesKey);
	    
	    String aesKeyS = Json.bytesToString(aesKey);
	    
	    if (!JedisWrapper.keySetNxExpire(jedis,"client:" + clientId + ":aesKey", aesKeyS, CLIENT_EXPIRE_SECONDS))
			return new DbResult(Errors.CLIENT_ENCRYPTION_SESSION_ALREADY_EXISTS);
		
	    DbResult result = new DbResult(Errors.SUCCESS);
	    result.clientId = clientId;
	    result.clientAesKey = aesKeyS;
	    
		return result;
	}
	
	public DbResult clientQuery(long clientId) {
		String clientKey = jedis.get("client:" + clientId + ":key");
		String keyId = jedis.get("client:" + clientId + ":keyId");
		String aesKey = jedis.get("client:" + clientId + ":aesKey");
		
		if (clientKey == null || keyId == null || aesKey == null)
			return new DbResult(Errors.CLIENT_ENCRYPTION_SESSION_NOT_FOUND);
		
		DbResult result = new DbResult(Errors.SUCCESS);
		
		result.clientId = clientId;
		result.clientAesKey = aesKey;
		result.clientKeyId = Long.parseLong(keyId);
		result.clientKey = clientKey;
		
		return result;
	}
	
	class ExpireUserKeysTask implements Runnable {
		private long uid = -1;
		public ExpireUserKeysTask(long uid) {
			this.uid = uid;
		}
		
		@Override
		public void run() {
			// TODO Auto-generated method stub
			Db db = new Db();
			if (db.init(CServer.getInstance().redisHost))
				db.expireUserKeysTask(uid);
		}
		
	}
	
	private void expireUserKeys(long uid, long timeout) {
		long count = jedis.llen("uid:" + uid + ":keys");
		long start = 0;
		Set<Long> found = new HashSet<Long>();
		do {
			List<String> ids = jedis.lrange("uid:" + uid + ":keys", start, start + REDIS_LRANGE_STEP);
			start+= REDIS_LRANGE_STEP;
			if ((ids == null) || (ids.size() == 0))
				break;
			
			for (String idS : ids) {
				found.add(Long.parseLong(idS));
			}
			
		} while (start < count);
		
		for (Long id : found) {
			String timeS = jedis.get("key:" + id + ":time");
			if (timeS != null) {
				long time = Long.parseLong(timeS);
				long currTime = System.currentTimeMillis();
				if ((time < currTime) && ((currTime - time) > timeout)) {
					if (CServer.isDebug())
						SLogger.d(TAG, "EXPIRE:delete key=" + id + " uid=" + uid);
					jedis.lrem("uid:" + uid + ":keys", 0, Long.toString(id));
					jedis.del("key:" + id + ":owner");
					jedis.del("key:" + id + ":time");
					keysDb.delete(uid, id);
				}
			}
		}
	}
	
	public void expireUserKeysTask(long uid) {
		// TODO Auto-generated method stub
		if (CServer.isDebug())
			SLogger.d(TAG, "expireUserKeysTask uid=" + uid);
		expireUserKeys(uid, KEY_TTL_MILLIS);
		expireUserMsgs(uid, MSG_TTL_MILLIS);
	}

	private void expireUserMsgs(long uid, long timeout) {
		long count = jedis.llen("uid:" + uid + ":messages");
		long start = 0;
		Set<Long> found = new HashSet<Long>();
		do {
			List<String> ids = jedis.lrange("uid:" + uid + ":messages", start, start + REDIS_LRANGE_STEP);
			start+= REDIS_LRANGE_STEP;
			if ((ids == null) || (ids.size() == 0))
				break;
			
			for (String idS : ids) {
				found.add(Long.parseLong(idS));
			}
			
		} while (start < count);
		
		for (Long id : found) {
			String timeS = jedis.get("message:" + id + ":time");
			if (timeS != null) {
				long time = Long.parseLong(timeS);
				long currTime = System.currentTimeMillis();
				if ((time < currTime) && ((currTime - time) > timeout)) {
					if (CServer.isDebug())
						SLogger.d(TAG, "EXPIRE:delete msg=" + id + " uid=" + uid);

					jedis.lrem("uid:" + uid + ":messages", 0, Long.toString(id));
					jedis.del("message:" + id + ":encKeyId");
					jedis.del("message:" + id + ":time");
					msgDb.delete(uid, id);
				}
			}
		}
	}
	
	public void expireKeysTask() {
		long usersCount = jedis.llen("users");
		long start = 0;
		Set<Long> foundUsers = new HashSet<Long>();
		do {
			List<String> users = jedis.lrange("users", start, start + REDIS_LRANGE_STEP);
			start+= REDIS_LRANGE_STEP;
			if ((users == null) || (users.size() == 0))
				break;
			
			for (String uidS : users) {
				foundUsers.add(Long.parseLong(uidS));
			}
		} while (start < usersCount);
		
		long delay = 1;
		for (Long uid : foundUsers) {
			CServer.getInstance().dbExpireExecService.schedule(new ExpireUserKeysTask(uid.longValue()), delay++, TimeUnit.SECONDS);
		}
	}

	public DbResult friendsQuery(DbUser user) {
		// TODO Auto-generated method stub
		
		long friendsCount = jedis.llen("uid:" + user.uid + ":friends");
		long start = 0;
		List<Long> friends = new ArrayList<Long>();
		do {
			List<String> friendsS = jedis.lrange("uid:" + user.uid + ":friends", start, start + REDIS_LRANGE_STEP);
			start+= REDIS_LRANGE_STEP;
			if ((friendsS == null) || (friendsS.size() == 0))
				break;
			
			for (String uidS : friendsS) {
				friends.add(Long.parseLong(uidS));
			}
		} while (start < friendsCount);
		
		DbResult result = new DbResult(Errors.SUCCESS);
		result.ids = friends;
		
		return result;
	}

	private void deleteFromAllFriends(long userId) {
		// TODO Auto-generated method stub
		while (true) {
			List<String> friendsS = jedis.lrange("uid:" + userId + ":friends", 0, REDIS_LRANGE_STEP);
			if ((friendsS == null) || (friendsS.size() == 0))
				break;
			
			for (String uidS : friendsS)
				friendRemoveInternal(userId, Long.parseLong(uidS));
		}
	}
	
	public DbResult friendInvites(DbUser user) {
		// TODO Auto-generated method stub
				
		long invitesCount = jedis.llen("uid:" + user.uid + ":invites");
		long start = 0;
		List<Long> invites = new ArrayList<Long>();
		do {
			List<String> invitesS = jedis.lrange("uid:" + user.uid + ":invites", start, start + REDIS_LRANGE_STEP);
			start+= REDIS_LRANGE_STEP;
			if ((invitesS == null) || (invitesS.size() == 0))
				break;
			
			for (String inviteS : invitesS) {
				invites.add(Long.parseLong(inviteS));
			}
		} while (start < invitesCount);
		
		DbResult result = new DbResult(Errors.SUCCESS);
		result.idsMap = new TreeMap<Long, Long>();
		
		for (Long inviteId : invites) {
			String uidS = jedis.get("invite:" + inviteId + ":uid");
			if (uidS != null)
				result.idsMap.put(inviteId, Long.parseLong(uidS));
			else
				jedis.lrem("uid:" + user.uid + ":invites", 0, Long.toString(inviteId));
		}
		
		return result;
	}

	public int friendInvite(DbUser user, long uid) {
		// TODO Auto-generated method stub
		if (uid == user.uid)
			return Errors.INVALID_REQUEST_PARAMETERS;
		
		if (!userAccActive(uid))
			return Errors.ACCOUNT_INVALID;
		
		long inviteId = jedis.incr("inviteId");
		
		JedisWrapper.keySetNxExpire(jedis, "invite:" + inviteId + ":uid", Long.toString(user.uid), INVITE_TTL_SECONDS);
		JedisWrapper.keySetNxExpire(jedis, "invite:" + inviteId + ":owner", Long.toString(uid), INVITE_TTL_SECONDS);
		
		jedis.lpush("uid:" + uid + ":invites", Long.toString(inviteId));
		
		return Errors.SUCCESS;
	}

	public int friendAccept(DbUser user, long inviteId, int accept) {
		// TODO Auto-generated method stub
		String onwerS = jedis.get("invite:" + inviteId + ":owner");
		String uidS = jedis.get("invite:" + inviteId + ":uid");
		
		if (onwerS == null || uidS == null)
			return Errors.OBJECT_NOT_FOUND;
		
		long owner = Long.parseLong(onwerS);
		long uid = Long.parseLong(uidS);
		
		if (owner != user.uid)
			return Errors.ACCESS_DENIED;
		
		long exists = jedis.lrem("uid:" + user.uid + ":invites", 0, Long.toString(inviteId));
		if (exists > 0 && accept > 0) {	
			jedis.sadd("uid:" + user.uid + ":friendsSet", Long.toString(uid));
			jedis.lpush("uid:" + user.uid + ":friends", Long.toString(uid));
			
			jedis.sadd("uid:" + uid + ":friendsSet", Long.toString(user.uid));			
			jedis.lpush("uid:" + uid + ":friends", Long.toString(user.uid));
		}
		
		jedis.del("invite:" + inviteId + ":owner");
		jedis.del("invite:" + inviteId + ":uid");
			
		return Errors.SUCCESS;
	}
	
	private void friendRemoveInternal(long userId, long friendId) {
		
		if (jedis.srem("uid:" + userId + ":friendsSet", Long.toString(friendId)) > 0)
			jedis.lrem("uid:" + userId + ":friends", 0, Long.toString(friendId));

		if (jedis.srem("uid:" + friendId + ":friendsSet", Long.toString(userId)) > 0)
			jedis.lrem("uid:" + friendId + ":friends", 0, Long.toString(userId));
	}
		
	public int friendRemove(DbUser user, long uid) {
		
		friendRemoveInternal(user.uid, uid);
		
		return Errors.SUCCESS;
		
	}
}

