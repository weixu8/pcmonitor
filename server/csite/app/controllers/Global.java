package controllers;

import play.*;
import play.mvc.Action;
import play.mvc.Http.Request;
import java.lang.reflect.Method;
import java.util.Map;

public class Global extends GlobalSettings {
	
    public Action onRequest(Request request, Method actionMethod) {
    	System.out.println("request=" + request.toString());
    	Map<String, String[]> headers = request.headers();
    	for (String key : headers.keySet()) {
    		System.out.println("header[" + key + "]=" + JsonHelper.stringArrToJson(headers.get(key)));
    	}

    	return super.onRequest(request, actionMethod);
    }
    
}