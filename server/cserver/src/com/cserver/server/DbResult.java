package com.cserver.server;

import java.util.List;
import java.util.Map;

import com.cserver.shared.Errors;
import com.cserver.shared.UserInfo;

public class DbResult {
	public DbUser user = null;
	public int error = Errors.UNSUCCESSFUL;
	public long clientId = -1;
	public String clientAesKey = null;
	public String clientKey = null;
	public long clientKeyId = -1;
	public UserInfo userInfo = null;
	public List<Long> ids = null;
	public Map<Long, Long> idsMap = null;
	
	public DbResult(int error) {
		this.error = error;
	}
}
