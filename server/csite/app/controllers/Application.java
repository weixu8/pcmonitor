package controllers;

import java.util.Map;

import com.cserver.shared.Db;
import com.cserver.shared.DbResult;
import com.cserver.shared.DbUser;
import com.cserver.shared.Errors;
import com.cserver.shared.IDbEnv;
import com.cserver.shared.JsonHelper;

import play.mvc.*;

import play.Play;
import views.html.*;

public class Application extends Controller {
	private static DbEnv dbEnv = new DbEnv();
	
	public static Db getDb() {
		return Db.getInstance(dbEnv);
	}
	
    public static Result root() {
    	return ok(root.render());
    }
    
    public static Result about() {
    	return ok(about.render());
    }

    public static Result login() {
    	return ok(login.render(""));
    }
    
    public static Result join() {
    	return ok(join.render(""));
    }
    
    public static Result doLogin() {
    	String json = request().body().asJson().toString();
    	
    	Map<String, String> map = JsonHelper.stringToMap(json);
    	System.out.println("email=" + map.get("email") + " pass=" + map.get("pass"));
    	Db db = getDb();
    	DbResult result = db.userAuthByNameAndPass(map.get("email"),  map.get("pass"));
    	if (result.error == Errors.SUCCESS) {
    		session("user", result.user.session);
    	}
    	return ok();
    }
    
    public static Result profile() {
    	String session = session("user");
    	
    	if (session == null) {
    		return redirect("/login");
    	}
    
    	Db db = getDb();
    	DbUser user = db.impersonate(session);
    	return ok(profile.render(user.username, user.uidS, user.session));
    }
    
    public static Result doJoin() {
    	String json = request().body().asJson().toString();
    	
    	Map<String, String> map = JsonHelper.stringToMap(json);
    	System.out.println("email=" + map.get("email") + " pass=" + map.get("pass") + " passCopy=" + map.get("passCopy"));

    	Db db = getDb();
    	int error = db.userAccountRegister(map.get("email"),  map.get("pass"));
    	
    	return ok();
    }
}
