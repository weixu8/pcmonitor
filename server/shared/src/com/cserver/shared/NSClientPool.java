package com.cserver.shared;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;



class TestThread implements Runnable {
	private static final String TAG = "ServerThread";
	private Thread thread = null;
	private volatile boolean stopping = false;
	private NSClientPool clientPool = null;
	
	public TestThread(NSClientPool clientPool) {
		this.thread = new Thread(this);
		this.clientPool = clientPool;
	}
	
	public void stop() {
		stopping = true;
	}
	
	public void start() {
		thread.start();
	}
	
	public void join() {
		boolean died = false;
		while (!died) {
			try {
				thread.join();
				died = true;
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}
		}
		
	}

	@Override
	public void run() {
		// TODO Auto-generated method stub
			
    	IRealClock clock = new JRealClock();
    	for (int i = 0; i < 100; i++) {
    		byte[] input = new byte[1024*1024];
			SecureRandom rng = new SecureRandom();
			rng.nextBytes(input);
			
    		//System.out.println("input=" + Utils.bytesToHex(input));
    		clock.start();    		
    		NSClientResult result = clientPool.sendReceive(input);
    		long time = clock.elapsedTime();
    		if (result.error != Errors.SUCCESS)
    			System.out.println("error=" + result.error);
    		else {   			
    			System.out.println("time=" + time + " output.length=" + result.output.length);
    			if (!Arrays.equals(input, result.output))
    				System.out.println("ARRAYS are NOT EQUAL");
    			//System.out.println("output=" + Utils.bytesToHex(result.output));
    		}
    	}
	}
}

class ConnectionsTask implements Runnable {
	private NSClientPool clientPool = null;
	
	public ConnectionsTask(NSClientPool clientPool) {
		this.clientPool = clientPool;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		this.clientPool.reopenConnections(1);
	}
}

public class NSClientPool {
	private static final String TAG = "NSClientPool";
	private int maxConnections = -1;
	private String host = null;
	private int port = -1;
	private Set<NSClient> clients = new TreeSet<NSClient>();
	private ScheduledExecutorService exec = null;
	private String ksPath = null;
	private String ksPass = null;
	private volatile boolean stopping = false;
	
	public NSClientPool(String host, int port, int maxConnections, String ksPath, String ksPass) {
		this.host = host;
		this.port = port;
		this.maxConnections = maxConnections;		
		this.ksPath = ksPath;
		this.ksPass = ksPass;
		this.stopping = false;
	}
	
	public void resume() {
		synchronized(this) {
			this.exec = Executors.newSingleThreadScheduledExecutor();
			this.exec.scheduleAtFixedRate(new ConnectionsTask(this), 0, 1000, TimeUnit.MILLISECONDS);
		}
		stopping = false;
	}
	
	public void pause() {
		stopping = true;
		synchronized(this) {
			exec.shutdown();
			try {
				exec.awaitTermination(1000, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}
			exec = null;
		}
	}
	
	public void closeConnections() {
		for (NSClient client : clients) {
			client.close();
		}
		clients.clear();
	}
	
	public void reopenConnections(int limit) {
		if (stopping)
			return;
		
		int reqNumConns = 0;
		synchronized(this) {
			if (!stopping && clients.size() < maxConnections)
				reqNumConns = maxConnections - clients.size();
		}
		
		for (int i = 0; i < Math.min(reqNumConns, limit); i++) {
			NSClient client = new NSClient(host, port, ksPath, ksPass);
			if (!client.connect()) {
				client.close();
				continue;
			} else {
				boolean added = false;
				synchronized(this) {
					if (!stopping) {
						clients.add(client);
						added = true;
					}
				}
				
				if (!added)
					client.close();
			}
		}
				
	}
	
	private NSClient lookupClient() {
		for (NSClient client : clients) {
			if (client.acquire())
				return client;
		}
		return null;
	}
	
	public NSClientResult sendReceive(byte[] input) {
		NSClientResult result = new NSClientResult();
		NSClient client = null;
		synchronized(this) {
			client = lookupClient();
		}
		
		if (client == null) {
			SLogger.i(TAG, "client lookup failed, will create new client");
			client = new NSClient(host, port, ksPath, ksPass);
			if (!client.connect()) {
				result.error = Errors.IO_ERROR;
				return result;
			}
			
			if (!client.acquire()) {
				client.close();
				result.error = Errors.IO_ERROR;
				return result;
			}
	
			synchronized(this) {
				clients.add(client);
			}
		}
		
		result = client.sendReceive(input);
		if (result.error != Errors.SUCCESS) {
			synchronized(this) {
				clients.remove(client);
			}
			client.close();
		}
		client.release();
		
		return result;
	}

	
    public static void main(String[] args) throws Exception {
    	SLogger.start(false, "c:\\cryptim_debug\\NSClientPool.log.txt", null);
		SLogger.i(TAG, "ClientPool starting ...");
    	
		NSClientPool clientPool = new NSClientPool("0.0.0.0", 8080, 60, "c:\\cryptim_debug\\client.bks", "1q2w3e");
		clientPool.resume();
		List<TestThread> threads = new ArrayList<TestThread>();
				
		for (int i = 0; i < 17; i++) {
			threads.add(new TestThread(clientPool));
		}
		
		SLogger.i(TAG, "starting threads");
		for (TestThread testThread : threads) {
			testThread.start();
		}
		
		SLogger.i(TAG, "joining threads");
		for (TestThread testThread : threads) {
			testThread.join();
		}
		
		SLogger.i(TAG, "pausing");
		clientPool.pause();
		SLogger.i(TAG, "paused");
	}
}
