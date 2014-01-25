package controllers;

import com.cserver.shared.IDbEnv;

import play.Play;

public class DbEnv implements IDbEnv {
	private String redisHost = null;
	private String dbPath = null;
	
	public String getRedisHost() {
		// TODO Auto-generated method stub
		if (redisHost != null)
			return redisHost;
		
		redisHost = Play.application().configuration().getString("redisHost");
		return redisHost;
	}
	
	@Override
	public String getWrkPath() {
		// TODO Auto-generated method stub
		if (dbPath != null)
			return dbPath;
		
		dbPath = Play.application().configuration().getString("dbPath");
		return dbPath;
	}
}
