package com.cserver.server;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import com.cserver.shared.FileOps;
import com.cserver.shared.IMapDumpable;
import com.cserver.shared.JsonHelper;

public class ServerConf implements IMapDumpable {

	public int debug = -1;
	public String redisHost = null;
	public int httpPort = -1;
	public String ksPath = null;
	public String ksPass = null;
	public String keyPass = null;
	public String ksType = null;
	
	@Override
	public boolean parseMap(Map<String, String> map) {
		// TODO Auto-generated method stub
		
		httpPort = Integer.parseInt(map.get("httpPort"));
		redisHost = map.get("redisHost");
		debug = Integer.parseInt(map.get("debug"));
		
		ksPath = map.get("ksPath");
		ksPass = map.get("ksPass");
		keyPass = map.get("keyPass");
		ksType = map.get("ksType");
		
		return true;
	}
	
	@Override
	public Map<String, String> toMap() {
		Map<String, String> map = new HashMap<String, String>();
		// TODO Auto-generated method stub
		map.put("httpPort", Integer.toString(httpPort));
		map.put("redisHost", redisHost);
		map.put("debug", Integer.toString(debug));
		map.put("ksPath", ksPath);
		map.put("ksPass", ksPass);
		map.put("keyPass", keyPass);
		map.put("ksType", ksType);
		
		return map;
	}
	
	public static ServerConf loadConf(String path, String confName) {
		File fpath = new File(path);
		File fconf = new File(fpath, confName);
		if (!fconf.exists())
			return null;
		
		String json = FileOps.readFile(fconf);
		if (json == null)
			return null;
		
		ServerConf conf = new ServerConf();
		conf.parseMap(JsonHelper.stringToMap(json));
		
		return conf;
	}
	
	
}
