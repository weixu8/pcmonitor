package com.cserver.shared;

import java.util.HashMap;
import java.util.Map;

public class SERequest implements IMapDumpable {
	public static final int TYPE_CLIENT_INVALID = -1;
	public static final int TYPE_CLIENT_REGISTER = 1;
	public static final int TYPE_CLIENT_DATA = 2;
	
	public int error = Errors.UNSUCCESSFUL;
	public int type = TYPE_CLIENT_INVALID;
	public String errorDetails = Errors.get(error);
	

	public String data = null;
	public long clientId = -1;
	
	public String clientKey = null;
	public long clientKeyId = -1;
	
	@Override
	public Map<String, String> toMap() {
		// TODO Auto-generated method stub
		
		Map<String, String> map = new HashMap<String, String>();
		map.put("data", data);
		
		map.put("clientId", Long.toString(clientId));
		map.put("clientKey", clientKey);
		map.put("clientKeyId", Long.toString(clientKeyId));

		map.put("type", Integer.toString(type));
		map.put("error", Integer.toString(error));
		map.put("errorDetails", errorDetails);
		
		return map;
	}
	
	@Override
	public boolean parseMap(Map<String, String> map) {
		// TODO Auto-generated method stub
		data = map.get("data");
		
		if (map.get("clientId") != null)
			clientId = Long.parseLong(map.get("clientId"));

		clientKey = map.get("clientKey");
		if (map.get("clientKeyId") != null)
			clientKeyId = Long.parseLong(map.get("clientKeyId"));
		
		type = Integer.parseInt(map.get("type"));
		error = Integer.parseInt(map.get("error"));
		errorDetails = map.get("errorDetails");
		
		return true;
	}
		
}
