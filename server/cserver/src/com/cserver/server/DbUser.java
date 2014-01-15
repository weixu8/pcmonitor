package com.cserver.server;

import com.cserver.shared.Errors;

public class DbUser {
	public String uidS = null;
	public String session = null;
	public String username = null;
	
	public long uid = -1;
	public Db db = null;
	public int error = Errors.UNSUCCESSFUL;
	
	DbUser(Db db, String uidS, String session, String username) {
		this.uidS = uidS;
		this.session = session;
		this.uid = Long.parseLong(uidS);
		this.db = db;
		this.username = username;
	}
}
