package controllers;

import java.util.Map;

import play.*;
import play.mvc.*;
import play.mvc.Http.RawBuffer;

import views.html.*;

public class Application extends Controller {
    public static Result root() {
    	return ok(root.render());
    }
    
    public static Result about() {
    	return ok(about.render());
    }

    public static Result login() {
    	return ok(login.render());
    }
    
    public static Result join() {
    	return ok(join.render());
    }
    
    public static Result doLogin() {
    	String json = request().body().asJson().toString();
    	
    	Map<String, String> map = JsonHelper.jsonToMap(json);
    	System.out.println("email=" + map.get("email") + " pass=" + map.get("pass"));
    	return redirect("/login");
    }
        
    public static Result doJoin() {
    	String json = request().body().asJson().toString();
    	
    	Map<String, String> map = JsonHelper.jsonToMap(json);
    	System.out.println("email=" + map.get("email") + " pass=" + map.get("pass") + " passCopy=" + map.get("passCopy"));
    	
    	return redirect("/join");
    }
}
