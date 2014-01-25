package controllers;

import play.*;
import play.mvc.Action;
import play.mvc.Http.Request;
import java.lang.reflect.Method;

public class Global extends GlobalSettings {
	
    public Action onRequest(Request request, Method actionMethod) {
    	System.out.println("request=" + request.toString() + " headers=" + JsonHelper.mapStoSArrToJson(request.headers()));

    	return super.onRequest(request, actionMethod);
    }
    
    public void onStart(play.Application app) {
      Logger.info("Application has started");
      System.out.println("Application has started");
      super.onStart(app);
    }  

    public void onStop(play.Application app) {
      Logger.info("Application shutdown...");
      System.out.println("Application shutdown ...");
      super.onStop(app);
    }
    
}