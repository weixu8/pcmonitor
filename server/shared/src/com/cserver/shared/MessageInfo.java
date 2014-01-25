package com.cserver.shared;

import java.util.HashMap;
import java.util.Map;

public class MessageInfo implements IMapDumpable {
	public long encKeyId = -1;
	public long msgId = -1;
	public byte bytes[] = null;
	@Override
	public Map<String, String> toMap() {
		// TODO Auto-generated method stub
		
		Map<String, String> map = new HashMap<String, String>();
		map.put("encKeyId", Long.toString(encKeyId));
		map.put("msgId", Long.toString(msgId));
		map.put("bytes", JsonHelper.bytesToString(bytes));
		
		return map;
	}
	@Override
	public boolean parseMap(Map<String, String> map) {
		// TODO Auto-generated method stub
		
		encKeyId = Long.parseLong(map.get("encKeyId"));
		msgId = Long.parseLong(map.get("msgId"));
		bytes = JsonHelper.stringToBytes(map.get("bytes"));
		
		return true;
	}
}
