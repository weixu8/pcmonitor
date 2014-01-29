package com.cserver.shared;


import java.util.TimeZone;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

public class Utils {

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	public static String currentTime() {
		// TODO Auto-generated method stub
		
	    DateTime dateTime = new DateTime(System.currentTimeMillis(),DateTimeZone.forTimeZone(TimeZone.getDefault()));
	    DateTimeFormatter timeFormater = DateTimeFormat.forPattern("yyyy-MM-dd HH:mm:ss,SSS");
	    
		return timeFormater.print(dateTime);
	}
	
	public static long parseTimeMillis(String date) {
		DateTimeFormatter timeFormater = DateTimeFormat.forPattern("yyyy-MM-dd HH:mm:ss,SSS");
		return timeFormater.parseMillis(date);
	}
}
