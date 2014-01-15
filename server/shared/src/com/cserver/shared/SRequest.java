package com.cserver.shared;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;


public class SRequest implements IMapDumpable {
	public static final int TYPE_INVALID = -1;
	public static final int TYPE_CRASH_REPORT = 1;
	public static final int TYPE_LOGOUT = 2;
	public static final int TYPE_PURCHASE_CONSUMED = 3;
	public static final int TYPE_PURCHASE_CREATE = 4;
	public static final int TYPE_PURCHASE_DATA_VERIFY = 5;
	public static final int TYPE_PURCHASE_FINISHED = 6;
	public static final int TYPE_PURCHASE_VERIFY = 7;
	public static final int TYPE_QUERY_MESSAGES = 9;
	public static final int TYPE_QUERY_MESSAGES_IDS = 10;
	public static final int TYPE_QUERY_USER = 11;
	public static final int TYPE_REGISTER = 13;
	public static final int TYPE_SEARCH_USERS = 14;
	public static final int TYPE_SEND_MESSAGE = 15;
	public static final int TYPE_SIGN_IN = 17;
	public static final int TYPE_ECHO = 19;
	public static final int TYPE_PUB_KEY_REGISTER = 20;
	public static final int TYPE_PUB_KEY_QUERY_BY_KEY_ID = 21;
	public static final int TYPE_PUB_KEY_QUERY_USER_CURRENT_KEY = 22;
	public static final int TYPE_DELETE = 23;
	public static final int TYPE_GET_CAPTCHA = 24;
	public static final int TYPE_PWD_CHANGE = 25;
	public static final int TYPE_UPDATE_PROFILE = 26;
	public static final int TYPE_QUERY_PROFILE = 27;
	
	public static final int TYPE_FRIEND_INVITE = 28;
	public static final int TYPE_FRIEND_ACCEPT = 29;
	public static final int TYPE_FRIENDS_QUERY = 30;
	public static final int TYPE_FRIEND_INVITES = 31;
	public static final int TYPE_FRIEND_REMOVE = 32;
	
	public String packetId = UUID.randomUUID().toString();

	private int error = Errors.UNSUCCESSFUL;
	private String errorDetails = Errors.get(Errors.UNSUCCESSFUL);
	private int type = TYPE_INVALID;
	private String session = null;
	
	public String username = null;
	public String email = null;
	public String password = null;
	public String newPassword = null;
	
	public String purchaseSku = null;
	public String purchaseId = null;
	public String purchaseData = null;
	public String purchaseDataSignature = null;
	public String purchaseInfo = null;
	
	public String report = null;
		
	public long lastMsgId = -1;
	public List<MessageInfo> messages = null;
	public List<Long> messagesIds = null;
	public byte[] message = null;
	public long msgId = -1;
	
	public long uid = -1;
	public String publicKey = null;
	public long keyId = -1;
	
	public List<Long> usersIds = null;
	public UserInfo profile = null;
	
	public long inviteId = -1;
	public Map<Long, Long> inviteMap = null;
		
	public byte[] captcha = null;
	public String captchaId = null;
	public String captchaAnswer = null;
	public int captchaOp = -1;
	
	public int accept = -1;
	
	public static final int CAPTCHA_OP_SIGNIN = 1;
	public static final int CAPTCHA_OP_DELETE = 3;
	public static final int CAPTCHA_OP_PWD_CHANGE = 4;
	private static final String TAG = "SRequest";
	
	public SRequest() {
		
	}
	public SRequest(int type) {
		this.type = type;
	}

	public int getType() {
		return type;
	}
	
	public void write(GZIPOutputStream os) throws IOException {
        String json = Json.mapToString(this.toMap());
        SPacket packet = new SPacket(json.getBytes("UTF-8"));
        SPacket.writeTo(os, packet);
	}
	
	public void read(GZIPInputStream is) throws IOException {
		SPacket packet = SPacket.readFrom(is);
		String json = new String(packet.data, "UTF-8");
		this.parseMap(Json.stringToMap(json));
	}
	
	public static SRequest requestFromBytes(byte[] input) {
		String json = null;
		//SLogger.d(TAG, "requestFromBytes:bytes=" + Utils.bytesToHex(input));
		try {
			json = new String(input, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (json == null) {
			SLogger.e(TAG, "string not decoded from bytes");
			return null;
		}
		//SLogger.d(TAG, "requestFromBytes:string=" + json);
		SRequest request = new SRequest();
		if (!request.parseMap(Json.stringToMap(json))) {
			SLogger.e(TAG, "request not decoded from string");
			return null;
		}
		
		return request;
	}
	
	public static byte[] requestToBytes(SRequest request) {
		byte[] output = null;		
		try {
			String outputS = Json.mapToString(request.toMap());
			//SLogger.d(TAG, "requestToBytes:string=" + outputS);
			output = outputS.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		//SLogger.d(TAG, "requestToBytes:bytes=" + Utils.bytesToHex(output));

		return output;
	}
	
	public static SRequest getErrorRequest(int error) {
		SRequest request = new SRequest();
		request.setError(error);
		return request;
	}
	
	public void setError(int error) {
		this.error = error;
		this.errorDetails = Errors.get(this.error);
	}
	
	public void setSession(String session) {
		this.session = session;
	}
	
	public String getSession() {
		return this.session;
	}
	
	public String getErrorDetails() {
		return this.errorDetails;
	}
	
	public int getError() {
		return this.error;
	}
	
	public void setError(int error, String errorDetails) {
		this.error = error;
		this.errorDetails = errorDetails;
	}
	
	public boolean isSessionRequired() {
		boolean sessionRequired = true;
		
		switch(type) {
		case TYPE_CRASH_REPORT:
		case TYPE_REGISTER:
		case TYPE_SIGN_IN:
		case TYPE_ECHO:
		case TYPE_GET_CAPTCHA:
			sessionRequired = false;
			break;
		default:
		}
		
		return sessionRequired;
	}
	
	public boolean isSSLRequired() {
		boolean sslRequired = true;
		
		switch(type) {
		case TYPE_CRASH_REPORT:
			sslRequired = false;
			break;
		default:
		}
		
		return sslRequired;
	}
	
	@Override
	public Map<String, String> toMap() {
		// TODO Auto-generated method stub
		Map<String, String> map = new HashMap<String, String>();

		map.put("packetId", packetId);
		map.put("error", Integer.toString(error));
		map.put("errorDetails", errorDetails);
		map.put("reqType", Integer.toString(type));
		map.put("session", session);
		
		map.put("username", username);
		map.put("password", password);
		map.put("email", email);
		
		map.put("report", report);
		
		map.put("uid", Long.toString(uid));
		map.put("accept", Integer.toString(accept));
		
		map.put("purchaseId", purchaseId);
		map.put("purchaseInfo", purchaseInfo);
		map.put("purchaseSku", purchaseSku);
		map.put("purchaseData", purchaseData);
		map.put("purchaseDataSignature", purchaseDataSignature);
		
		
		if (profile != null)
			map.put("profile", Json.mapToString(profile.toMap()));
		else
			map.put("profile", null);
		
		map.put("lastMsgId", Long.toString(lastMsgId));
		map.put("msgId", Long.toString(msgId));
		
		if ((messages != null) && (messages.size() > 0))
			map.put("messages", Json.messageInfoListToString(messages));
		else
			map.put("messages", null);
		
		if ((messagesIds != null) && (messagesIds.size() > 0))
			map.put("messagesIds", Json.longListToString(messagesIds));
		else
			map.put("messagesIds", null);
		
		if ((usersIds != null) && (usersIds.size() > 0))
			map.put("usersIds", Json.longListToString(usersIds));
		else
			map.put("usersIds", null);
		
		if (message != null)
			map.put("message", Json.bytesToString(message));
		else
			map.put("message", null);
				
		map.put("publicKey", publicKey);
		
		map.put("keyId", Long.toString(keyId));
		
		
		if (captcha != null)
			map.put("captcha", Json.bytesToString(captcha));
		else
			map.put("captcha", null);
		
		map.put("captchaId", captchaId);
		map.put("captchaAnswer", captchaAnswer);
		map.put("captchaOp", Integer.toString(captchaOp));
		map.put("newPassword", newPassword);
		
		if (inviteMap != null)
			map.put("inviteMap", Json.mapLLToString(inviteMap));
		else
			map.put("inviteMap", null);
		
		map.put("inviteId", Long.toString(inviteId));
		
		return map;
	}
	
	@Override
	public boolean parseMap(Map<String, String> map) {
		// TODO Auto-generated method stub
		
		packetId = map.get("packetId");
		error = Integer.parseInt(map.get("error"));
		errorDetails = map.get("errorDetails");
		type = Integer.parseInt(map.get("reqType"));
		session = map.get("session");
		
		username = map.get("username");
		password = map.get("password");
		email = map.get("email");
		
		report = map.get("report");
		
		purchaseId = map.get("purchaseId");
		purchaseInfo = map.get("purchaseInfo");
		purchaseSku = map.get("purchaseSku");
		purchaseData = map.get("purchaseData");
		purchaseDataSignature = map.get("purchaseDataSignature");
		
		uid = Long.parseLong(map.get("uid"));
		
		if (map.get("profile") != null) {
			profile = new UserInfo();
			profile.parseMap(Json.stringToMap(map.get("profile")));
		}
		
		lastMsgId = Long.parseLong(map.get("lastMsgId"));
		msgId = Long.parseLong(map.get("msgId"));
		
		if (map.get("messages") != null)
			messages = Json.stringToMessageInfoList(map.get("messages"));
		
		if (map.get("messagesIds") != null)
			messagesIds = Json.stringToLongList(map.get("messagesIds"));
		
		if (map.get("usersIds") != null)
			usersIds = Json.stringToLongList(map.get("usersIds"));
		
		if (map.get("message") != null)
			message = Json.stringToBytes(map.get("message"));
		
		publicKey = map.get("publicKey");
		
		if (map.get("keyId") != null)
			keyId = Long.parseLong(map.get("keyId"));
		
		if (map.get("captcha") != null)
			captcha = Json.stringToBytes(map.get("captcha"));
		
		captchaAnswer = map.get("captchaAnswer");
		captchaId = map.get("captchaId");
		captchaOp = Integer.parseInt(map.get("captchaOp"));
		newPassword = map.get("newPassword");
		
		if (map.get("inviteMap") != null)
			inviteMap = Json.stringToLLMap(map.get("inviteMap"));
		
		inviteId = Long.parseLong(map.get("inviteId"));
		accept = Integer.parseInt(map.get("accept"));
		
		return true;
	}
	
}
