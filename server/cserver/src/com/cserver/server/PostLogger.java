package com.cserver.server;

import java.util.TimeZone;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.cserver.shared.SPostLogger;

public class PostLogger implements SPostLogger {

	@Override
	public void debugMessage(String tag, String message) {
		// TODO Auto-generated method stub
//		Logger.debug("DEBUG:" + tag + ":" + message);
	}

	@Override
	public void errorMessage(String tag, String message) {
		// TODO Auto-generated method stub
//		Logger.error("ERROR:" + tag + ":" + message);		
	}

	@Override
	public void exceptionMessage(String tag, Exception e) {
		// TODO Auto-generated method stub
//		StringWriter sw = new StringWriter();
//		PrintWriter pw = new PrintWriter(sw);
//		e.printStackTrace(pw);

//		Logger.error("EXCP:" + tag + ":" + e.toString() + " stack:" + pw.toString());
	}

	@Override
	public void infoMessage(String tag, String message) {
		// TODO Auto-generated method stub
//		Logger.info("INFO:" + tag + ":" + message);
	}

	@Override
	public void verboseMessage(String tag, String message) {
		// TODO Auto-generated method stub
//		Logger.info("VERB:" + tag + ":" + message);
	}

	@Override
	public String currentTime() {
		// TODO Auto-generated method stub
		
	    DateTime dateTime = new DateTime(System.currentTimeMillis(),DateTimeZone.forTimeZone(TimeZone.getDefault()));
	    DateTimeFormatter timeFormater = DateTimeFormat.forPattern("yyyy-MM-dd HH:mm:ss,SSS");
	        
		return timeFormater.print(dateTime);
	}

	@Override
	public void throwableMessage(String tag, Throwable throwable) {
		// TODO Auto-generated method stub
		
	}
}
