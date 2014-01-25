package com.cserver.server;

import java.io.File;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.cserver.shared.DataCrypt;
import com.cserver.shared.Db;
import com.cserver.shared.FileCache;
import com.cserver.shared.IDbEnv;
import com.cserver.shared.Json;
import com.cserver.shared.MessageCrypt;
import com.cserver.shared.NSServer;
import com.cserver.shared.SLogger;

public class CServer implements IDbEnv {
	private static final String TAG = "CServer";
	private static volatile CServer instance = null;
	public FileCache fileCache = null;
	public String path = null;
    public String base64EncodedAppPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkAuIp3OBZaiaqAtWgQ4Qru9ilgWUz6eKyp0q6BEa1MJjZ6G1IWcNPG3rVW9Ss/O7KdddjeG/oMHD9FW5n9hvXOQuzejJp5vhaQ3Rd5S0cvpEMdkGVkQjBa2/m1D7Ums5/ov2Ntb7809U/ZpsCplw+5X1zf/d9xvADqBRAb2ZRuVKPAuQaB7lveNcgUKlpVKo1CnkEPyGxjQ1sK/WrB2eNkezqsBAT+AauRkBRrnhDws2ZL4G56l1vNOmqHz78XwZQlIVHSLbiQQEvLi+FJTsho6yKQDuJtBwxAwxg3tboL+j9TRl3SeXgwtf1ZBvlg5HQXll6z4xgxgsvafV2di9KwIDAQAB";
    public String redisHost = null;
    public ScheduledExecutorService execService = null;
    public ScheduledExecutorService dbExpireExecService = null;
    public static final String srvPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtOFrurs9bumiw/Dq2gvs2w+VF5BjfgV3/o091WznL+YDenQNqK04tHz/AcF+A1fzNJibDhrDfvYgQQNjskkOKxtsQbWOUQ4dOErJLRIS6WU5NoXJKVW4BwSTeiBAuiECBpXrnPvoqwyI+HDAtg+kQZbhqelIorlabuEmudLZshlZ541xvxOP6V74d8rLbZlFNCmmFunDdBxIvoll+u3st21rpa8SCwRkpVqBIZop1sO3dwRbIvTV3ICqvuYAIS5CpbmPkEHq11408iyanJIykaqLZzkuE2LWaENtt9bdkOVeZaFJ+gqGolJXeBZgHnklycC7AThH/np7qOuvyrt5TwIDAQAB";
    public static final String srvPrivKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC04Wu6uz1u6aLD8OraC+zbD5UXkGN+BXf+jT3VbOcv5gN6dA2orTi0fP8BwX4DV/M0mJsOGsN+9iBBA2OySQ4rG2xBtY5RDh04SsktEhLpZTk2hckpVbgHBJN6IEC6IQIGleuc++irDIj4cMC2D6RBluGp6UiiuVpu4Sa50tmyGVnnjXG/E4/pXvh3ysttmUU0KaYW6cN0HEi+iWX67ey3bWulrxILBGSlWoEhminWw7d3BFsi9NXcgKq+5gAhLkKluY+QQerXXjTyLJqckjKRqotnOS4TYtZoQ2231t2Q5V5loUn6CoaiUld4FmAeeSXJwLsBOEf+enuo66/Ku3lPAgMBAAECggEBAJ+ct3qclVZVFor/Ac6NbWHU+0RC5nijDML0EddOdSdAOluJIzBwQrSKBGChRLhgmL0V2OV2WoKjX8ze18/QRY9mcH3/XulJoiE1ZRa/dy67YuQo5Fz0RiLzN8wxv8w/KlFzY+kwJZ0iv48zt+owHUq/gLx1neHx28oyJgEd/Xn5Ba0z2oqcl4B+bzi0x1IoBECcg3IPukZtNSW+RxiNpTKG7aFi7HDaGyYntBC15x+MckORoJuLhZjqbczcWen2gJwm0d887489be+sFvXB158AXtbUWehZ3t2qMsaSUVx6ZxdSSvaDSq18LNFZhpjiCBUizADMv+y5KHcoXbC2EHECgYEA6vYMzPrq0odqSi959aRqaYpt39TdKE+e3cf5QyMG56Tudd10IjPM3dj0RYT4f5X/qINu6Tcw2I9iQ+pY8KdjDQN9ta5BIazeIiZi1RSBApvLcbBor5v7M5zz4E6hOrWwK5xEfWNaFq+qzp9Gj4K5kMoMsa4RrcjvqDdnxstiJNkCgYEAxROyRJlG9dX6yndzgBpl5vPmOeX6S7WU2aX6R6/+FX+6eewDXW3J1CY3stD+tv/3Jc5y4E3ejavin/kgyx4Nnb8iPhpVZODoFixUa/C8tOmR2vpovy5533ft5uyTWpvxTJz050lwGVKrhq4Q7WSzHdqL0JygSNTIhjtOh4M0FmcCgYAGylGYYvACYZN6zWBy7ut8XVnLjDVQAu0Ob8cOX6bFbwjNMzc1/dU/3BNDJxKfbVBUKGg+KTAqMgqe99jWK6A7MgyiAYU0WfCZgA5/JfaMgsAgav67hIB//1s08lDKh5Gt0PhRv1tNKIqBKi053IdMXep8ABHWueXjMKa5IguWEQKBgQCXTkPzvupoG9zsTUFz/NB3vJHpqdO9BLA/WdsJ5ujggKwep0D+HihypNTmiObGgUay1AoGhEJ16p2XzKGM0IoLro8PtxAQ30vQmkBGjxGSpDDDOrXo8jnHhEA2pzOKwWdFNswgNpXGG15tjH6ahFGwffYSN+4nfJZn2Gi2SdlXyQKBgBJqyRCpZPXJhPKPAHdmjuhknT+sxNfaMasiVqbu9wVwVo04bYb3s318dfH8UuFXJfVHGffl85EfTjvtgTI8GSMXzzo/OW1/YYOXYWeI9i0yOvEfWsbfXU5C9UibL4knhPmC4VWB8LaYhB9iR/mWoa7zHg5Tjo6pgzCXcisjtbTe";
    public volatile boolean debug = false;
    public File wrkPathFile = null;
    
	public static CServer getInstance() {
		if (instance != null)
			return instance;
		
		synchronized(CServer.class) {
			if (instance == null) {
				instance = new CServer();
			}
		}
		
		return instance;
	}
	
	public static boolean isDebug() {
		return getInstance().debug;
	}
	
	private void shutdown() {
	}
	
	public boolean start(ServerConf conf, String path) {
		this.path = path;
		this.debug = (conf.debug > 0) ? true : false;
		this.redisHost = conf.redisHost;
		
		SLogger.start(!this.debug, new File(this.path, "server.log").getAbsolutePath(), new PostLogger());
		SLogger.getInstance().setLogSize(3000000);
		SLogger.i(TAG, "server starting...");
		
		execService = Executors.newScheduledThreadPool(16);
		dbExpireExecService = Executors.newScheduledThreadPool(16);
		
		
		Db db = Db.getInstance(this);
		if (db == null) {
			shutdown();
			return false;
		}
		
		MessageCrypt.init(this.debug);
		DataCrypt.init(this.debug);
		
		SLogger.i(TAG, "server started");
		return true;
	}
	
    public static void main(String[] args) throws Exception {
		String wrkPath = null;
		
		for (int i = 0; i < args.length; i++) {
			System.out.println("args[" + i + "]=" + args[i]);
		}

		if (args.length != 2) {
			System.out.println("Args.length=" + args.length);
			System.exit(-1);
			return;
		}
		
		if (args[0].equals("--path")) {
			wrkPath = args[1];
		} else {
			System.out.println("path not specified");
			System.exit(-1);
			return;
		}
		
		
		File wrkPathFile = new File(wrkPath);
		if (!wrkPathFile.exists()) {
			System.out.println("path =" + wrkPathFile.getAbsolutePath() + " not exists");
			System.exit(-1);
			return;
		}
        
		if (!wrkPathFile.isDirectory()) {
    		System.out.println("path =" + wrkPathFile.getAbsolutePath() + " not a directory");
			System.exit(-1);
			return;
		}
        
		ServerConf conf = ServerConf.loadConf(wrkPathFile.getAbsolutePath(), "cserver.conf");
		if (conf == null) {
			System.out.println("cant read conf file, path=" + wrkPathFile.getAbsolutePath());
			System.exit(-1);
			return;	
		}
		
		System.out.println("Loaded conf=" + Json.mapToString(conf.toMap()));
		
    	if (!CServer.getInstance().start(conf, wrkPathFile.getAbsolutePath())) {
    		System.out.println("server not started");
			System.exit(-1);
    		return;
    	}
   	
        new NSServer(conf.httpPort).run(new CServerHandler(), new File(wrkPathFile, conf.ksPath).getAbsolutePath(), conf.ksPass, conf.keyPass, conf.ksType);
    	//new NSServer(conf.httpPort).run(new CServerHandler(), null, null, null);

    }

	@Override
	public String getRedisHost() {
		// TODO Auto-generated method stub
		return redisHost;
	}

	@Override
	public String getWrkPath() {
		// TODO Auto-generated method stub
		return wrkPathFile.getAbsolutePath();
	}
}