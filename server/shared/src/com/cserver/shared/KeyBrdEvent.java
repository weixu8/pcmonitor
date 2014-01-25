package com.cserver.shared;

import java.util.HashMap;
import java.util.Map;


public class KeyBrdEvent implements IMapDumpable {
	public int makeCode = -1;
	public int keyUp = -1;
	public int flags = -1;
	public int keyE0 = -1;
	public int keyE1 = -1;

	public String sysTime = null;
	public String buffer = null;

	@Override
	public boolean parseMap(Map<String, String> map) {
		// TODO Auto-generated method stub
		buffer = map.get("buffer");
		sysTime = map.get("sysTime");
		
		makeCode = Integer.parseInt(map.get("makeCode"));
		keyUp = Integer.parseInt(map.get("keyUp"));
		flags = Integer.parseInt(map.get("flags"));
		keyE0 = Integer.parseInt(map.get("keyE0"));
		keyE1 = Integer.parseInt(map.get("keyE1"));
		
		return true;
	}

	@Override
	public Map<String, String> toMap() {
		// TODO Auto-generated method stub
		
		Map<String, String> map = new HashMap<String, String>();
		
		map.put("buffer", buffer);
		map.put("sysTime", sysTime);
		map.put("makeCode", Integer.toString(makeCode));
		map.put("keyUp", Integer.toString(keyUp));
		map.put("flags", Integer.toString(flags));
		map.put("keyE0", Integer.toString(keyE0));
		map.put("keyE1", Integer.toString(keyE1));

		return map;
	}

}
