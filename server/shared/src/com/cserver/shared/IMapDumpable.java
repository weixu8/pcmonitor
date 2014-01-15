package com.cserver.shared;

import java.util.Map;

public interface IMapDumpable {
	public Map<String, String> toMap();
	public boolean parseMap(Map<String, String> map);
}

