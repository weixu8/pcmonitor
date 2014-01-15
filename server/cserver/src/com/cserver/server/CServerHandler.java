package com.cserver.server;


import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import org.apache.commons.mail.EmailException;

import com.cserver.shared.CaptchaResult;
import com.cserver.shared.DataCrypt;
import com.cserver.shared.IKeyResolver;
import com.cserver.shared.INSServerHandler;
import com.cserver.shared.JRealClock;
import com.cserver.shared.Json;
import com.cserver.shared.KeyQuery;
import com.cserver.shared.LastError;
import com.cserver.shared.MessageInfo;
import com.cserver.shared.SLogger;
import com.cserver.shared.SRequest;
import com.cserver.shared.Errors;
import com.cserver.shared.UserInfo;
import com.cserver.shared.SERequest;
import com.cserver.shared.Utils;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;



class EmailCrashReportTask implements Runnable {

	private static final String TAG = "EmailCrashReportTask";
	private File reportFile = null;
	private String reportId = null;
	
	EmailCrashReportTask(File reportFile, String reportId) {
		this.reportFile = reportFile;
		this.reportId = reportId;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		try {
			Email.sendEmail(reportFile.getAbsolutePath(), "report", "report_" + reportId + "_.txt", 
					Settings.devEmail, 
					"New crash report id=" + reportId + " time=" + new PostLogger().currentTime(), 
					"report id is " + reportId,
					Settings.serverEmailAcc,
					Settings.serverEmailAccPass
				);
		} catch (EmailException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
	}
}


public class CServerHandler implements INSServerHandler {

	private static final String TAG = "ServerHandleRequest";
	private static Gson gson = new Gson();
		

	@Override
	public byte[] handle(byte[] input) {
		// TODO Auto-generated method stub
		
		//SLogger.d(TAG, "handle:input=" + Utils.bytesToHex(input));
		//JRealClock clock = new JRealClock();
		//clock.start();
		
		SRequest request = null;
		request = SRequest.requestFromBytes(input);		
		if (request == null) {
			SLogger.e(TAG, "input not decoded");
			return SRequest.requestToBytes(SRequest.getErrorRequest(Errors.STRING_ENCODING_ERROR));
		}
		
		SRequest response = handleRequest(request);
		if (response == null) {
			SLogger.e(TAG, "no response");
			return null;
		}
		
		byte[] output = SRequest.requestToBytes(response);		
		if (output == null) {
			SLogger.e(TAG, "no output constructed");
			return SRequest.requestToBytes(SRequest.getErrorRequest(Errors.STRING_ENCODING_ERROR));
		}
		
		//SLogger.d(TAG, "handle:output=" + Utils.bytesToHex(input));
		//SLogger.i(TAG, "request " + request.getType() + " time=" + clock.elapsedTime());
		
		return output; 
	}
	
	public String handleClientJson(String requestJson) {
		String responseJson = null;
		try {
			SERequest request = new SERequest();
			SERequest response = null;
		
			request.parseMap(Json.stringToMap(requestJson));
	
			response = this.handleSE(request);
			
			responseJson = Json.mapToString(response.toMap());
		
		} catch (Exception e) {
			SLogger.exception(TAG, e);
			SLogger.e(TAG, "request handling failed with exception " + e.toString());
			return null;
		}
		
		return responseJson;
	}
	
	private class ServerKeyResolver implements IKeyResolver {
		private static final String TAG = "ServerKeyResolver";
		@Override
		public PrivateKey getPrivateKey(long ownerId, long keyId) {
			// TODO Auto-generated method stub
			if ((ownerId == 0) && (keyId == 0)) {
				return Json.stringToPrivateKey(CServer.getInstance().srvPrivKey);
			} else {
				SLogger.e(TAG, "cant get private key onwerId=" + ownerId + " keyId=" + keyId);
				return null;
			}
		}

		@Override
		public PublicKey getPublicKey(long ownerId, long keyId) {
			// TODO Auto-generated method stub
			if ((ownerId == 0) && (keyId == 0)) {
				return Json.stringToPublicKey(CServer.getInstance().srvPubKey);
			} else {
				Db db = new Db();
				if (!db.init(CServer.getInstance().redisHost)) {
					SLogger.e(TAG, "cant connect redis host");
					return null;
				}
				
				DbResult result = db.clientQuery(ownerId);
				if (result.error != Errors.SUCCESS) {
					SLogger.e(TAG, "db.clientQuery for id=" + ownerId + " failed with err=" + result.error);
					return null;
				}
				
				if (result.clientKeyId != keyId) {
					SLogger.e(TAG, "onwer=" + ownerId + " clientKeyId=" + result.clientKeyId + " .vs keyId=" + keyId);
					return null;
				}
				
				return Json.stringToPublicKey(result.clientKey);
			}
		}
	}
	
	private SERequest clientRegister(Db db, SERequest request) {
		try {
			if ((request.clientKey == null) || (request.clientKeyId == -1)) {
				SLogger.e(TAG, "invalid params:clientKey=" + request.clientKey + " clientKeyId=" + request.clientKeyId);
				request.error = Errors.INVALID_REQUEST_PARAMETERS;
				return request;
			}
			
			DbResult result = db.clientRegister(request.clientKey, request.clientKeyId);
			if (result.error != Errors.SUCCESS) {
				SLogger.e(TAG, "clientRegister failed for clientKey=" + request.clientKey + " clientKeyId=" + request.clientKeyId
						+ " with error=" + result.error);
				request.error = result.error;
				return request;
			}
		
			request.clientId = result.clientId;
			byte []clientAesKey = DataCrypt.RsaEncryptData(
					request.clientKeyId, result.clientId, 0, 0, 
					Json.stringToBytes(result.clientAesKey), new ServerKeyResolver());
			
			if (clientAesKey == null) {
				SLogger.e(TAG, "RsaEncryptData for aes key failed");
				request.error = Errors.INTERNAL_SERVER_ERROR;
				return request;
			}
			
			request.data = Json.bytesToString(clientAesKey);
			request.error = Errors.SUCCESS;
			
		} catch (Exception e) {
			SLogger.exception(TAG, e);
			SLogger.e(TAG, "exception=" + e.toString());
			request.error = Errors.INTERNAL_SERVER_ERROR;
		}
		
		return request;
	}
	
	private SERequest clientData(Db db, SERequest request) {
		try {
			if (request.clientId == -1) {
				SLogger.e(TAG, "invalid client id=" + request.clientId);
				request.error = Errors.INVALID_REQUEST_PARAMETERS;
				return request;
			}
			
			DbResult result = db.clientQuery(request.clientId);
			if (result.error != Errors.SUCCESS) {
				SLogger.e(TAG, "clientQuery failed for client id=" + request.clientId);
				request.error = result.error;
				return request;
			}
			
			byte[] aesKey = Json.stringToBytes(result.clientAesKey);
			byte[] plainData = DataCrypt.AesDecryptData(aesKey, Json.stringToBytes(request.data), new ServerKeyResolver());
			if (plainData == null) {
				SLogger.e(TAG, "AesDecryptData failed for client id=" + request.clientId);
				request.error = Errors.AES_MSG_DECRYPT_FAILED;
				return request;
			}
			
			SRequest sRequest = new SRequest();
			SRequest sResponse = null;
			sRequest.parseMap(Json.stringToMap(new String(plainData, "UTF-8")));
			
			sResponse = handleRequest(sRequest);
			String jsonResponse = Json.mapToString(sResponse.toMap());					
					
			byte[] encrypted = DataCrypt.AesEncryptData(aesKey, 0, 0, 
					jsonResponse.getBytes("UTF-8"), new ServerKeyResolver());
			
			if (encrypted == null) {
				SLogger.e(TAG, "AesEncryptData failed for client id=" + request.clientId);
				request.error = Errors.INTERNAL_SERVER_ERROR;
				return request;
			}
			
			request.data = Json.bytesToString(encrypted);
			request.error = Errors.SUCCESS;

		} catch (Exception e) {
			SLogger.exception(TAG, e);
			SLogger.e(TAG, "exception=" + e.toString());
			request.error = Errors.INTERNAL_SERVER_ERROR;
		}
		
		return request;
	}
	
	private SERequest handleSE(SERequest request) {
		Db db = new Db();
		if (!db.init(CServer.getInstance().redisHost)) {
			return null;
		}
		
		switch (request.type) {
			case SERequest.TYPE_CLIENT_REGISTER:
				request = clientRegister(db, request);
				break;
			case SERequest.TYPE_CLIENT_DATA:
				request = clientData(db, request);
				break;
			default:
				SLogger.e(TAG, "invalid request type=" + request.type);
				request.error = Errors.INVALID_REQUEST_TYPE;
				break;		
		}
		
		return request;
	}


	private SRequest handleRequest(SRequest request) {
		long t1 = System.currentTimeMillis();
		
		String session = request.getSession();
	
		if (CServer.isDebug())
			SLogger.i(TAG, "handle request type=" + request.getType() + " session=" + session);

		
		if (request.isSessionRequired() && (session == null)) {
			request.setError(Errors.SESSION_REQUIRED);
			return request;
		}
		
		Db db = new Db();
		if (!db.init(CServer.getInstance().redisHost)) {
			request.setError(Errors.INTERNAL_SERVER_ERROR);
			return request;
		}
		
		DbUser user = null;
		
		user = db.impersonate(session);
		if (user == null) {
			if (request.isSessionRequired()) {
				request.setError(Errors.SESSION_REQUIRED);
				return request;
			}
		} else if (user.error != Errors.SUCCESS) {
			request.setError(user.error);
			return request;
		}
		
		request.setSession(null);
		
		int error = Errors.UNSUCCESSFUL;
		
		switch(request.getType()) {
		case SRequest.TYPE_ECHO:
			error = echo(db, user, request);
			break;
		case SRequest.TYPE_CRASH_REPORT:
			error = crashReport(db, user, request);
			break;
		case SRequest.TYPE_LOGOUT:
			error = logout(db, user, request);
			break;
		case SRequest.TYPE_PURCHASE_CONSUMED:
			error = purchaseConsumed(db, user, request);
			break;
		case SRequest.TYPE_PURCHASE_CREATE:
			error = purchaseCreate(db, user, request);
			break;
		case SRequest.TYPE_PURCHASE_DATA_VERIFY:
			error = purchaseDataVerify(db, user, request);
			break;
		case SRequest.TYPE_PURCHASE_FINISHED:
			error = purchaseFinished(db, user, request);
			break;
		case SRequest.TYPE_PURCHASE_VERIFY:
			error = purchaseVerify(db, user, request);
			break;
		case SRequest.TYPE_QUERY_MESSAGES:
			error = queryMessages(db, user, request);
			break;
		case SRequest.TYPE_QUERY_MESSAGES_IDS:
			error = queryMessagesIds(db, user, request);
			break;
		case SRequest.TYPE_QUERY_USER:
			error = queryUserInfo(db, user, request);
			break;
		case SRequest.TYPE_REGISTER:
			error = register(db, user, request);
			break;
		case SRequest.TYPE_SEARCH_USERS:
			error = searchUsers(db, user, request);
			break;
		case SRequest.TYPE_SEND_MESSAGE:
			error = sendMessage(db, user, request);
			break;
		case SRequest.TYPE_SIGN_IN:
			error = signin(db, user, request);
			break;
		case SRequest.TYPE_PUB_KEY_REGISTER:
			error = pubKeyRegister(db, user, request);
			break;
		case SRequest.TYPE_PUB_KEY_QUERY_BY_KEY_ID:
			error = pubKeyQueryByKeyId(db, user, request);
			break;
		case SRequest.TYPE_PUB_KEY_QUERY_USER_CURRENT_KEY:
			error = pubKeyQueryUserCurrentKey(db, user, request);
			break;
		case SRequest.TYPE_DELETE:
			error = delete(db, user, request);
			break;
		case SRequest.TYPE_GET_CAPTCHA:
			error = getCaptcha(db, user, request);
			break;
		case SRequest.TYPE_PWD_CHANGE:
			error = pwdChange(db, user, request);
			break;
		case SRequest.TYPE_UPDATE_PROFILE:
			error = updateProfile(db, user, request);
			break;	
		case SRequest.TYPE_QUERY_PROFILE:
			error = queryProfile(db, user, request);
			break;
		case SRequest.TYPE_FRIEND_ACCEPT:
			error = friendAccept(db, user, request);
			break;
		case SRequest.TYPE_FRIEND_INVITE:
			error = friendInvite(db, user, request);
			break;
		case SRequest.TYPE_FRIEND_INVITES:
			error = friendInvites(db, user, request);
			break;
		case SRequest.TYPE_FRIENDS_QUERY:
			error = friendsQuery(db, user, request);
			break;
		case SRequest.TYPE_FRIEND_REMOVE:
			error = friendRemove(db, user, request);
			break;
		default:
			error = Errors.INVALID_REQUEST_TYPE;
			break;
		}
		
		request.setError(error);
		long t2 = System.currentTimeMillis();
	
		if (CServer.isDebug())
			SLogger.i(TAG, "time per request=" + (t2 - t1) + " ms.");
		return request;
	}
	
	private int friendsQuery(Db db, DbUser user, SRequest request) {
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		DbResult result = db.friendsQuery(user);
		if (result.error == Errors.SUCCESS) {
			request.usersIds = result.ids;
		} 
		
		return result.error;
	}

	private int friendInvites(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		DbResult result = db.friendInvites(user);
		if (result.error == Errors.SUCCESS) {
			request.inviteMap = result.idsMap;
		} 
		
		return result.error;
	}

	private int friendInvite(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		int error = db.friendInvite(user, request.uid);
		
		return error;
	}

	private int friendAccept(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		int error = db.friendAccept(user, request.inviteId, request.accept);
		
		return error;
	}

	private int friendRemove(Db db, DbUser user, SRequest request) {
		if (user == null)
			return Errors.SIGNIN_REQUIRED;
		
		int error = db.friendRemove(user, request.uid);
		return error;
	}
	
	private int pwdChange(Db db, DbUser user, SRequest request) {
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		DbResult result = db.pwdChange(user, request.username, request.password, 
				request.newPassword, request.captchaId, request.captchaAnswer);
		if (result.error != Errors.SUCCESS) {
			SLogger.e(TAG, "pwdChange error= " + result.error);
		} else {
			request.setSession(result.user.session);
			request.uid = result.user.uid;
		}
		
		return result.error;
	}
	
	private int getCaptcha(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		CaptchaResult result = db.getCaptcha(user, request.captchaOp);
		if (result.error != Errors.SUCCESS) {
			SLogger.e(TAG, "getCaptcha error= " + result.error);
			return result.error;
		} 
		
		request.captcha = result.captchaBytes;
		request.captchaId = result.captchaId;
		
		return result.error;
	}
	
	private int delete(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		int error = db.deleteUser(user, request.username, request.password, 
				request.captchaId, request.captchaAnswer);
		if (error != Errors.SUCCESS) {
			SLogger.e(TAG, "deleteUser error= " + error);
		} else {
			request.uid = user.uid;
		}

		return error;

	}

	private int pubKeyRegister(Db db, DbUser user, SRequest request) {
		int error = Errors.UNSUCCESSFUL;
		
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		error = db.pubKeyRegister(user, request.publicKey, request.keyId);
		if (error != Errors.SUCCESS) {
			SLogger.e(TAG, "pubKeyRegister error= " + error);
		}
		
		return error;
	}
	
	private int pubKeyQueryByKeyId(Db db, DbUser user, SRequest request) {
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		KeyQuery result = db.pubKeyQueryByKeyId(user, request.uid, request.keyId);
		if (result.error == Errors.SUCCESS) {
			request.publicKey = result.publicKey;
			request.keyId = result.keyId;
		}
		
		return result.error;
	}
	
	private int pubKeyQueryUserCurrentKey(Db db, DbUser user, SRequest request) {
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		KeyQuery result = db.pubKeyQueryUserCurrentKey(user, request.uid);
		if (result.error == Errors.SUCCESS) {
			request.publicKey = result.publicKey;
			request.keyId = result.keyId;
		}
		
		return result.error;
	}
	
	private int echo(Db db, DbUser user, SRequest request) {
		SLogger.i(TAG, "echo request");
		return Errors.SUCCESS;
	}
	
	private int crashReport(Db db, DbUser user, SRequest request) {
		String reportJson = request.report;
		if (reportJson == null) {
			SLogger.e(TAG, "no crash report");
			return Errors.INVALID_REQUEST_PARAMETERS;
		}
		
		Map<String, String> reportMap = null;
		
		try {
			reportMap = gson.fromJson(reportJson, new TypeToken<Map<String, String>>(){}.getType());
		} catch (Exception e) {
			SLogger.exception(TAG, e);
		}
		
		String reportId = null;
		if ((reportMap == null) || ((reportId = reportMap.get("REPORT_ID")) == null)) {
			SLogger.e(TAG, "invalid crash report");
			return Errors.INVALID_REQUEST_PARAMETERS;
		}
		
		File reportsDir = new File(CServer.getInstance().path, "reports");
		if (!reportsDir.exists()) {
			reportsDir.mkdir();
		}
		
		File reportFile = new File(reportsDir, reportId + ".report.log");
		FileOutputStream os = null;
		boolean crashReportDone = false;
		try {
			os = new FileOutputStream(reportFile);
			os.write(reportJson.getBytes("UTF-8"));
			crashReportDone = true;
			os.flush();
		} catch(IOException e) { 
			SLogger.exception(TAG, e);
		} finally {
			if (os != null) {
				try {
					os.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					SLogger.exception(TAG, e);
				}
			}
		}
		
		if (crashReportDone)
			CServer.getInstance().execService.submit(new EmailCrashReportTask(reportFile, reportId));
		
		return Errors.SUCCESS;
	}

	private int purchaseCreate(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		int error = Errors.UNSUCCESSFUL;
		if (user != null) {
			String purchaseId = db.purchaseCreate(user, request.purchaseSku);
			if (purchaseId == null)
				error = LastError.get();
			else {
				request.purchaseId = purchaseId;
				error = Errors.SUCCESS;
			}
		} else
			error = Errors.SIGNIN_REQUIRED;
		
		return error;
	}

	private int signin(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		int error = Errors.UNSUCCESSFUL;
		DbResult result = db.userAuthByNameAndPass(request.username, request.password);
		
		if (result.error != Errors.SUCCESS)
			return result.error;
		
		if (result.user != null) {
			request.setSession(result.user.session);
			request.uid = result.user.uid;
			error = Errors.SUCCESS;
		} else {
			SLogger.e(TAG, "signin:result.user = null !!!");
			error = Errors.INTERNAL_SERVER_ERROR;
		}
		
		return error;
	}

	private int sendMessage(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		long msgId = db.sendMessage(user, request.uid, request.message, request.keyId);
		if (msgId > 0) {
			request.msgId = msgId;
			return Errors.SUCCESS;
		} else {
			return Errors.INTERNAL_SERVER_ERROR;
		}
	}

	private int searchUsers(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		int error = Errors.UNSUCCESSFUL;
		List<Long> usersIds = db.searchUsers(user, request.profile);
		if (usersIds == null || usersIds.size() == 0)
			error = Errors.NOTHING_WAS_FOUND;
		else {
			request.usersIds = usersIds;
			error = Errors.SUCCESS;
		}
		
		return error;
	}

	private int register(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		int error = db.userAccountRegister(request.username, request.password);
		if (error == Errors.SUCCESS) {
			DbResult result = db.userAuthByNameAndPass(request.username, request.password);
			if (result.error != Errors.SUCCESS)
				return result.error;
			
			if (result.user != null) {
				request.setSession(result.user.session);
				request.uid = result.user.uid;
				error = Errors.SUCCESS;
			} else {
				SLogger.e(TAG, "register:result.user = null !!!");
				error = Errors.INTERNAL_SERVER_ERROR;
			}
		} 
		
		return error;
	}

	private int updateProfile(Db db, DbUser user, SRequest request) {
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		if (request.profile == null) {
			return Errors.INVALID_REQUEST_PARAMETERS;
		}
		
		int result = db.updateProfile(user, request.profile);
		
		return result;
	}
	
	private int queryProfile(Db db, DbUser user, SRequest request) {
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		UserInfo profile = db.queryProfile(user);
		if (profile != null) {
			request.profile = profile;
			return Errors.SUCCESS;
		} else {
			return Errors.INTERNAL_SERVER_ERROR;
		}
	}
	
	private int queryUserInfo(Db db, DbUser user,
			SRequest request) {
		// TODO Auto-generated method stub
		
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		if (request.uid < 0) {
			return Errors.INVALID_REQUEST_PARAMETERS;
		}
		
		DbResult result = db.queryUserInfo(user, request.uid);
		if (result.error != Errors.SUCCESS) {
			return result.error;
		}
		
		request.profile = result.userInfo;
		
		return Errors.SUCCESS;
	}

	private int queryMessagesIds(Db db, DbUser user,
			SRequest request) {
		// TODO Auto-generated method stub
		
		int error = Errors.UNSUCCESSFUL;
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		return error;
	}

	private int queryMessages(Db db, DbUser user,
			SRequest request) {
		// TODO Auto-generated method stub
		if (user == null) {
			return Errors.SIGNIN_REQUIRED;
		}
		
		List<MessageInfo> messages = db.queryMessages(user, request.lastMsgId);
		if ((messages == null) || (messages.size() == 0)) {
			if (CServer.isDebug())
				SLogger.d(TAG, "messages not found");
			return Errors.NOTHING_WAS_FOUND;
		} else {
			request.messages = messages;
			return Errors.SUCCESS;
		}
	}

	private int purchaseVerify(Db db, DbUser user,
			SRequest request) {
		// TODO Auto-generated method stub
		int error = Errors.UNSUCCESSFUL;
		if (user != null)
			error = db.purchaseVerify(user, request.purchaseId);
		else
			error = Errors.SIGNIN_REQUIRED;
		
		return error;
	}

	private int purchaseFinished(Db db, DbUser user,
			SRequest request) {
		// TODO Auto-generated method stub
		int error = Errors.UNSUCCESSFUL;
		if (user != null)
			error = db.purchaseFinished(user, request.purchaseId, request.purchaseInfo);
		else
			error = Errors.SIGNIN_REQUIRED;
		
		return error;
	}

	private int purchaseDataVerify(Db db, DbUser user,
			SRequest request) {
		// TODO Auto-generated method stub
		int error = Errors.UNSUCCESSFUL;
		if (user != null)
			error = db.purchaseDataVerify(user, request.purchaseData, request.purchaseDataSignature);
		else
			error = Errors.SIGNIN_REQUIRED;
		
		return error;
	}


	private int purchaseConsumed(Db db, DbUser user,
			SRequest request) {
		// TODO Auto-generated method stub
		int error = Errors.UNSUCCESSFUL;
		if (user != null)
			error = db.purchaseConsumed(user, request.purchaseId, request.purchaseInfo);
		else
			error = Errors.SIGNIN_REQUIRED;
		
		return error;
		
	}

	private int logout(Db db, DbUser user, SRequest request) {
		// TODO Auto-generated method stub
		int error = Errors.UNSUCCESSFUL;
		if (user != null)
			error = db.logout(user);
		else
			error = Errors.SIGNIN_REQUIRED;
		
		return error;
	}
}
