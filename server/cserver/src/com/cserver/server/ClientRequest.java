package com.cserver.server;

import java.util.HashMap;
import java.util.Map;

import com.cserver.shared.Base64;
import com.cserver.shared.Base64DecoderException;
import com.cserver.shared.IMapDumpable;
import com.cserver.shared.SLogger;


public	class ClientRequest implements IMapDumpable {
	private static final String TAG = "ClientRequest";
	public int type = -1;
	public int status = -1;
	public byte[] data = null;
	
	public String clientId = null;
	public String authId = null;
	public String hostId = null;
	
	public String userSid = null;
	public String userName = null;
	public String programName = null;
	public String windowTitle = null;
	public String systemTime = null;
	
	public int sessionId = -1;
	public int pid = -1;
	public int tid = -1;
	
	public static final int TYPE_BASE = 0x900;
	public static final int TYPE_UNDEFINED = TYPE_BASE+1;
	public static final int TYPE_ECHO = TYPE_BASE+2;
	public static final int TYPE_KEYBRD = TYPE_BASE+3;
	public static final int TYPE_SCREENSHOT = TYPE_BASE+4;
	public static final int TYPE_USER_WINDOW = TYPE_BASE+5;
	
	public static final int STATUS_SUCCESS = 0x0;
	public static final int STATUS_ERROR = 0xD0000000;
	public static final int STATUS_ERROR_UNDEFINED = STATUS_ERROR + 1;
	public static final int STATUS_ERROR_NOT_SUPPORTED = STATUS_ERROR + 2;
	public static final int STATUS_ERROR_JSON_DECODE = STATUS_ERROR + 3;
	public static final int STATUS_ERROR_NO_MEM = STATUS_ERROR + 4;
	public static final int STATUS_ERROR_NO_RESPONSE = STATUS_ERROR + 5;
	
	public ClientRequest()
	{
		type = TYPE_UNDEFINED;
		status = STATUS_ERROR_UNDEFINED;
		data = null;
	}
	
	@Override
	public Map<String, String> toMap() {
		// TODO Auto-generated method stub
		Map<String, String> map = new HashMap<String, String>();
		map.put("type", Integer.toString(type));
		map.put("status", Integer.toString(status));
		
		if (data != null)
			map.put("data", Base64.encode(data));
		
		map.put("clientId", clientId);
		map.put("authId", authId);
		map.put("hostId", hostId);
		
		
		map.put("sessionId", Integer.toString(sessionId));
		map.put("pid", Integer.toString(pid));
		map.put("tid", Integer.toString(tid));
		
		map.put("userSid", userSid);
		map.put("userName", userName);
		map.put("programName", programName);
		map.put("windowTitle", windowTitle);
		map.put("systemTime", systemTime);
		
		return map;
	}

	@Override
	public boolean parseMap(Map<String, String> map) {
		// TODO Auto-generated method stub
		type = Integer.parseInt(map.get("type"));
		status = Integer.parseInt(map.get("status"));
		
		clientId = map.get("clientId");		
		authId = map.get("authId");
		hostId = map.get("hostId");
		
		String sessionIdS = map.get("sessionId");
		if (sessionIdS != null)
			sessionId = Integer.parseInt(sessionIdS);
		
		String pidS = map.get("pid");
		if (pidS != null)
			pid = Integer.parseInt(pidS);
		
		String tidS = map.get("tid");
		if (tidS != null)
			tid = Integer.parseInt(tidS);
		
		userSid = map.get("userSid");
		userName = map.get("userName");
		programName = map.get("programName");
		windowTitle = map.get("windowTitle");
		systemTime = map.get("systemTime");
		
		String encodedData = map.get("data");
		if (encodedData != null) {
			try {
				data = Base64.decode(encodedData);
			} catch (Base64DecoderException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}
		} else {
			data = null;
		}
		
		return true;
	}

	public static ClientRequest clone(ClientRequest request)
	{
		ClientRequest clone = new ClientRequest();
		clone.parseMap(request.toMap());
		
		return clone;
	}
}
