package com.cserver.shared;

import java.util.HashMap;
import java.util.Map;

public class UserInfo implements IMapDumpable {
	public static final int TYPE_FRIEND = 1;
	public static final int TYPE_OTHER = 2;
	
	public static final long GENDER_MALE = 0;
	public static final long GENDER_FEMALE = 1;
	public static final long GENDER_OTHER = 2;
	public static final long GENDER_ANY = 3;
	
	public String username = null;	
	public long accessTime = -1;
	public long uid = -1;
	public int type = -1;
	public String extraS = null;
	public long extraL = -1;
	
	public long age = -1;
	public long gender = -1;

	public String school = null;
	public String job = null;
	public String jobTitle = null;
	public String aboutMe = null;
	public String interests = null;
	public String hobby = null;
	
	public byte[] picBytes = null;
	
	
	public long keyId = -1;
	public String key = null;
	
	
	@Override
	public Map<String, String> toMap() {
		// TODO Auto-generated method stub
		Map<String, String> map = new HashMap<String, String>();
		map.put("username", username);
		map.put("accessTime", Long.toString(accessTime));
		map.put("type", Integer.toString(type));
		map.put("uid", Long.toString(uid));
		
		map.put("age", Long.toString(age));
		map.put("gender", Long.toString(gender));
		map.put("school", school);
		map.put("job", job);
		map.put("jobTitle", jobTitle);
		map.put("aboutMe", aboutMe);
		map.put("interests", interests);
		map.put("hobby", hobby);
		
		map.put("keyId", Long.toString(keyId));
		map.put("key", key);
		
		if (picBytes != null)
			map.put("picBytes", Json.bytesToString(picBytes));
		
		if (extraS != null)
			map.put("extraS", extraS);
		else
			map.put("extraS", null);
		
		map.put("extraL", Long.toString(extraL));
		
		return map;
	}
	
	@Override
	public boolean parseMap(Map<String, String> map) {
		// TODO Auto-generated method stub
		username = map.get("username");
		accessTime = Long.parseLong(map.get("accessTime"));
		type = Integer.parseInt(map.get("type"));
		uid = Long.parseLong(map.get("uid"));
		extraS = map.get("extraS");
		extraL = Long.parseLong(map.get("extraL"));
		
		age = Long.parseLong(map.get("age"));
		gender = Long.parseLong(map.get("gender"));
		school = map.get("school");
		job = map.get("job");
		jobTitle = map.get("jobTitle");
		aboutMe = map.get("aboutMe");
		interests = map.get("interests");
		hobby = map.get("hobby");
		
		if (map.get("picBytes") != null) {
			picBytes = Json.stringToBytes(map.get("picBytes"));
		}
		
		key = map.get("key");
		keyId = Long.parseLong(map.get("keyId"));
		
		return true;
	}
}
