package controllers;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.cserver.shared.Db;
import com.cserver.shared.DbHost;
import com.cserver.shared.DbResult;
import com.cserver.shared.DbScrnshot;
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
    	session().remove("user");
    	return ok(login.render());
    }
    
    public static Result join() {
    	session().remove("user");
    	return ok(join.render());
    }
    
    public static Result currUser() {
    	String session = session("user");
    	DbUser user = null;
    	if (session == null) {
    		user = null;
    	} else {
    		Db db = getDb();
    		user = db.impersonate(session);
    	}
    	return ok(jsonUser(user));
    }
    
    public static Result doLogout() {
    	session().remove("user");
    	return redirect("/");
    }
    
    public static String jsonUser(DbUser user) {
    	Map<String, String> map = new HashMap<String, String>();
    	if (user != null) {
    		map.put("uid", user.uidS);
    		map.put("username", user.username);
    		map.put("session", user.session);
    		map.put("clientId", user.clientId);
    		map.put("authId", user.authId);
    	} else {
    		map.put("uid", "-1");
    	}
    	
		return JsonHelper.mapToString(map);
    }
    
    public static String jsonError(int error) {
    	Map<String, String> map = new HashMap<String, String>();
    	map.put("error", Integer.toString(error));
    	map.put("errorS", Errors.get(error));
    	return JsonHelper.mapToString(map);
    }
    
    public static Result doLogin() {
    	session().remove("user");
    	String json = request().body().asJson().toString();
    	
    	Map<String, String> map = JsonHelper.stringToMap(json);
    	System.out.println("email=" + map.get("email") + " pass=" + map.get("pass"));
    	Db db = getDb();
    	DbResult result = db.userAuthByNameAndPass(map.get("email"),  map.get("pass"));
    	if (result.error == Errors.SUCCESS) {
    		session("user", result.user.session);
    	}
    	    	
    	return ok(jsonError(result.error));
    }
    
    public static Result profile() {
    	String session = session("user");
    	if (session == null)
    		return redirect("/login");
    	
		Db db = getDb();
		DbUser user = db.impersonate(session);
		if (user == null)
			return redirect("/login");
		
		Set<String> hosts = db.getHosts(user.clientId);

    	return ok(profile.render(hosts));
    }
    
    public static Result doJoin() {
    	session().remove("user");
    	String json = request().body().asJson().toString();
    	
    	Map<String, String> map = JsonHelper.stringToMap(json);
    	System.out.println("email=" + map.get("email") + " pass=" + map.get("pass") + " passCopy=" + map.get("passCopy"));

    	Db db = getDb();
    	int error = db.userAccountRegister(map.get("email"),  map.get("pass"));
    	
    	return ok(jsonError(error));
    }
    
    public static Result host(String hostId) {
    	String session = session("user");
    	if (session == null)
    		return redirect("/login");
    	
		Db db = getDb();
		DbUser user = db.impersonate(session);
		if (user == null)
			return redirect("/login");

		DbHost host = db.refHost(user, hostId);
		if (host == null)
			return ok(hostv.render(hostId, "Information about this host doesn't exists."));
				
		return ok(hostv.render(hostId, ""));
    }
    
    public static Result screenshot(String hostId, long id) {
      	String session = session("user");
    	if (session == null)
    		return notFound();
    	
		Db db = getDb();
		DbUser user = db.impersonate(session);
		if (user == null)
			return notFound();
		
		DbHost host = db.refHost(user, hostId);
		if (host == null)
			return notFound();

    	DbScrnshot screen = db.hostScreenshot(host, id);
    	return ok(screen.file);
    }
    
    public static Result screenshots(String hostId, int start, int end) {
    	String session = session("user");
    	Map<String, String> map = new HashMap<String, String>();
    	map.put("error", "-1");
    	
    	if (session == null)
    		return ok(JsonHelper.mapToString(map));
    	
		Db db = getDb();
		DbUser user = db.impersonate(session);
		if (user == null)
			return ok(JsonHelper.mapToString(map));
		
		DbHost host = db.refHost(user, hostId);
		if (host == null)
			return ok(JsonHelper.mapToString(map));
		
		List<Long> ids = db.hostScreenshots(host, start, end);
		Map<Long, String> idsToTime = new HashMap<Long, String>();
		for (Long id : ids) {
			DbScrnshot screen = db.hostScreenshot(host, id);
			idsToTime.put(id, screen.time);
		}
		
		map.put("error", "0");		
		map.put("ids", JsonHelper.longListToString(ids));
		map.put("idsToTime", JsonHelper.mapLStoString(idsToTime));
		
		return ok(JsonHelper.mapToString(map));
    }
}
