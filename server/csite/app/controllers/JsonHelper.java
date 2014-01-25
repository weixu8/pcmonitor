package controllers;

import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class JsonHelper {
	private static Gson gson = new Gson();
	
	public static String stringArrToJson(String[] arr) {
		return gson.toJson(arr);
	}
	
	public static String[] jsonToStringArr(String json) {
		String[] arr = new Gson().fromJson(json, new TypeToken<String[]>(){}.getType());
		return arr;
	}
		
	public static String mapStoSArrToJson(Map<String, String[]> map) {
		return gson.toJson(map);
	}
	
	
	public static Map<String, String> jsonToMap(String json) {
		Map<String, String> map = new Gson().fromJson(json, new TypeToken<Map<String, String>>(){}.getType());
		return map;
	}
}
