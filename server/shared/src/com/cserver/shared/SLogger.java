package com.cserver.shared;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;


class MsgWriteTask implements Runnable {
	SLogger log = null;
	public MsgWriteTask(SLogger log) {
		this.log = log;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		this.log.processMsgQueue();
	}
	
}

public class SLogger {

	private File logFile = null;
	
	private final ReentrantReadWriteLock msgQueueRWLock = new ReentrantReadWriteLock();
	private final Lock msgQueueReadLock  = msgQueueRWLock.readLock();
	private final Lock msgQueueWriteLock = msgQueueRWLock.writeLock();
	
	private final ReentrantReadWriteLock logFileRWLock = new ReentrantReadWriteLock();
	private final Lock logFileWriteLock = logFileRWLock.writeLock();
	
	private boolean releaseBuild = false;
    private static volatile SLogger instance;
    private static final int LOG_FILE_SIZE_LIMIT = 512000;
    private String logPath = "log.log";
    private SPostLogger postLogger = null;
    private ExecutorService exec = null;
    private int logSize = LOG_FILE_SIZE_LIMIT;
    
    
    private LinkedList<String> msgQueue = new LinkedList<String>();
    
	private File getFile() {
		return new File(logPath);
	}
	
	private File getSavedFile() {
		return new File(logPath + ".old.log");		
	}
	
	public static SLogger getInstance() {
		if (instance != null)
			return instance;
		
		synchronized(SLogger.class) {
			if (instance == null) {
				instance = new SLogger();
			}
		}
		
		return instance;
	}
	
	public SLogger() {
	}
	
	private void startInstance(boolean releaseBuild, String logPath, SPostLogger postLogger) {
		synchronized(this) {
			this.logPath = new File(logPath).getAbsolutePath();
			this.logFile = getFile();
			this.postLogger = postLogger;
			this.releaseBuild = releaseBuild;
			this.exec = Executors.newSingleThreadExecutor();
			this.msgQueue.clear();
		}
	}
	
	private void rotate() {
		if (!getFile().exists())
			return;
		
		if (getFile().length() < logSize)
			return;
		
		if (getSavedFile().exists())
			getSavedFile().delete();
		
		getFile().renameTo(getSavedFile());
		logFile = getFile();
	}
	
	private void putMessage(String message) {
		String postMessage = (postLogger != null) ? (postLogger.currentTime() + ":" + message) : message;
		
		msgQueueWriteLock.lock();
		try {
			msgQueue.add(postMessage);
		} finally {
			msgQueueWriteLock.unlock();
		}
		
		if (msgQueue.size() == 0)
			return;
		
		msgQueueReadLock.lock();
		try {
			if (msgQueue.size() > 0)
				exec.submit(new MsgWriteTask(this));
		} finally {
			msgQueueReadLock.unlock();
		}
	}
	
	public void processMsgQueue() {
		if (msgQueue.size() == 0)
			return;
		
		LinkedList<String> msgs = new LinkedList<String>();

		msgQueueWriteLock.lock();
		try {
			if (msgQueue.size() > 0) {
				while (msgQueue.size() > 0) {
					String msg = msgQueue.removeFirst();
					msgs.add(msg);
				}
			}
		} finally {
			msgQueueWriteLock.unlock();
		}
		
		if (msgs.size() == 0)
			return;

		while (msgs.size() > 0) {
			String msg = msgs.removeFirst();
			writeMessageToLog(msg);
		}
		
	}
	
	private void writeMessageToLog(String message) {	
		logFileWriteLock.lock();
		try {
			rotate();
			BufferedWriter out = null;
			try {
		    	out = new BufferedWriter(new FileWriter(logFile, true));
	    		out.write(message + '\n');
		    	out.flush();
			} catch (IOException e) {
			} finally {
				if (out != null)
					try {
						out.close();
					} catch (IOException e1) {
						e1.printStackTrace();
					}
			}		
		} finally {
			logFileWriteLock.unlock();
		}
	}
	
	public void debugMessage(String tag, String message) {
		if (this.releaseBuild)
			return;
		putMessage("DEBUG:" + tag + ":" + message);
		if (!this.releaseBuild)
			if (postLogger != null)
				postLogger.debugMessage(tag, message);
	}

	public void errorMessage(String tag, String message) {
		putMessage("ERROR:" + tag + ":" + message);
		if (postLogger != null)
			postLogger.errorMessage(tag, message);
	}

	public void infoMessage(String tag, String message) {
		putMessage("INFO:" + tag + ":" + message);
		if (postLogger != null)
			postLogger.infoMessage(tag, message);
	}

	public void verboseMessage(String tag, String message) {
		if (this.releaseBuild)
			return;
		putMessage("VERB:" + tag + ":" + message);
		if (!this.releaseBuild)
			if (postLogger != null)
				postLogger.verboseMessage(tag, message);
	}
	
	public void exceptionMessage(String tag, Exception e) {
		Writer sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		e.printStackTrace(pw);

		putMessage("EXCP:" + tag + ":" + e.toString() + " stack:" + sw.toString());

		if (!this.releaseBuild)
			if (postLogger != null)
				postLogger.exceptionMessage(tag, e);
	}
	
	public void throwableMessage(String tag, Throwable t) {
		Writer sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		t.printStackTrace(pw);

		putMessage("THRW:" + tag + ":" + t.toString() + " stack:" + sw.toString());

		if (!this.releaseBuild)
			if (postLogger != null)
				postLogger.throwableMessage(tag, t);
	}
	
	public static void e(String tag, String message) {
		SLogger.getInstance().errorMessage(tag, message);
	}
	
	public static void i(String tag, String message) {
		SLogger.getInstance().infoMessage(tag, message);
	}

	public static void v(String tag, String message) {
		SLogger.getInstance().verboseMessage(tag, message);
	}
	
	public static void d(String tag, String message) {
		SLogger.getInstance().debugMessage(tag, message);
	}
	
	public static void exception(String tag, Exception e) {
		SLogger.getInstance().exceptionMessage(tag, e);
	}
	
	public static void throwable(String tag, Throwable t) {
		SLogger.getInstance().throwableMessage(tag, t);
	}
	
	
	public static void start(boolean releaseBuild, String logPath, SPostLogger postLogger) {
		SLogger.getInstance().startInstance(releaseBuild, logPath, postLogger);
	}
	
	public void setLogSize(int logSize) {
		if (logSize > LOG_FILE_SIZE_LIMIT)
			this.logSize = logSize;
	}
	
	private List<String> getLastLinesToList(File file, int numLines) {
		List<String> lines = new LinkedList<String>();
        FileInputStream in = null;
        BufferedReader br = null;
		try {
			in = new FileInputStream(file);
			br = new BufferedReader(new InputStreamReader(in));
			
			for(String tmp; (tmp = br.readLine()) != null;) 
				if (lines.add(tmp) && lines.size() > numLines) 
					lines.remove(0);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (in != null)
				try {
					in.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			
			if (br != null)
				try {
					br.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
		
		return lines;
	}
	
	public String instanceGetLastLines(int numLines) {  
		StringBuilder builder = new StringBuilder();
		List<String> lines = null, linesSaved = null;
		synchronized(this) {
			if (getFile().exists())
				lines = getLastLinesToList(getFile(), numLines);
			
			if (lines.size() < numLines)
				if (getSavedFile().exists())
					linesSaved = getLastLinesToList(getFile(), numLines - lines.size());			
		}
		
		if (linesSaved != null)
			for (String line : linesSaved) {
				builder.append(line + '\n');
			}
		
		if (lines != null)
			for (String line : lines) {
				builder.append(line + '\n');
			}
		
		return builder.toString();		
	}
	
	public static String getLastLines(int numLines) {
		return SLogger.getInstance().instanceGetLastLines(numLines);
	}
}
