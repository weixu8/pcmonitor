package controllers;

import play.*;
import play.mvc.Action;
import play.mvc.Http.Request;

import java.io.File;
import java.lang.reflect.Method;

import com.cserver.shared.JsonHelper;
import com.cserver.shared.SLogger;

public class Global extends GlobalSettings {
	
    private static final String TAG = "Global";

	public Action onRequest(Request request, Method actionMethod) {
    	System.out.println("request=" + request.toString() + " headers=" + JsonHelper.mapStringToStringArrToJson(request.headers()));
    	SLogger.i(TAG, "request=" + request.toString() + " headers=" + JsonHelper.mapStringToStringArrToJson(request.headers()));
    	return super.onRequest(request, actionMethod);
    }
    
    public void onStart(play.Application app) {
		 DbEnv db = new DbEnv();
		  
		 SLogger.start(false, new File(db.getWrkPath(), "csite.log").getAbsolutePath(), new PostLogger());
		 SLogger.getInstance().setLogSize(3000000);
		 SLogger.i(TAG, "csite starting...");
		
		 super.onStart(app);
    }  

    public void onStop(play.Application app) {
  	  	SLogger.i(TAG, "csite stopping...");
  	  
    	super.onStop(app);
    }
    
}