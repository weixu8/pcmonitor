package com.cserver.shared;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class NSClient implements Comparable<NSClient> {
	private static final String TAG = "NSClient";
	private String host = null;
	private int port = -1;
	private Socket socket = null;
	private BufferedOutputStream os = null;
	private BufferedInputStream is = null;	
	public volatile AtomicInteger refCount = new AtomicInteger(0);
	private long id = -1;
	private String ksPath = null;
	private String ksPass = null;
	
	public NSClient(String host, int port, String ksPath, String ksPass) {
		this.host = host;
		this.port = port;
		this.ksPath = ksPath;
		this.ksPass = ksPass;
		this.id = MessageCrypt.getRndLong();
	}
	
	public boolean connect() {
		SLogger.i(TAG, "connecting client with id=" + id);
		
		boolean result = false;
		try {
			if (ksPath != null)
				this.socket = SSLSocketLib.createClientSocketAndHandshake(host, port, ksPath, ksPass);
			else
				this.socket = new Socket(host, port);
			
			this.socket.setTcpNoDelay(true);
			this.os = new BufferedOutputStream(socket.getOutputStream());
			this.is = new BufferedInputStream(socket.getInputStream());
			
			result = true;
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} finally {
			if (!result && this.socket != null)
				try {
					this.socket.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					SLogger.exception(TAG, e);
				}
		}
		
		SLogger.i(TAG, "connected client with id=" + id + " result=" + result);
		return result;
	}
	
	
	public int readIS(InputStream is, byte []buff, int size) throws IOException {
		int read = 0;
		int off = 0;
		
		while (size > off) {
			read = is.read(buff, off, size - off);
			if (read == -1)
				break;
			off+= read;
		}
		
		return off;
	}
	
	public void close() {	
		SLogger.i(TAG, "closing client with id=" + id);
		if (is != null)
			try {
				is.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}
		
		if (os != null)
			try {
				os.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}
		
		if (socket != null)
			try {
				socket.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}	
		
		SLogger.i(TAG, "closed client with id=" + id);
	}
	
	public boolean acquire() {
		return refCount.compareAndSet(0, 1);
	}
	
	public void release() {
		refCount.compareAndSet(1, 0);
	}
	
	public NSClientResult sendReceive(byte[] input) {
		NSClientResult result = new NSClientResult();
		result.error = Errors.UNSUCCESSFUL;
		byte[] output = null;
		try {			
			NSPacketHeader header = new NSPacketHeader(input.length);
			byte[] rawHeader = header.toBytes();
			os.write(rawHeader, 0, rawHeader.length);
			os.write(input, 0, input.length);
			os.flush();		
			if (rawHeader.length == readIS(is, rawHeader, rawHeader.length)) {
				header = NSPacketHeader.fromBytes(rawHeader);
				if (header.size == 0) {
					SLogger.e(TAG, "no data from server");
					result.output = null;
					result.error = Errors.SUCCESS;
				} else {
					output = new byte[header.size];
					if (output.length != readIS(is, output, output.length)) {	
						output = null;
						result.error = Errors.IO_ERROR;
						SLogger.e(TAG, "cant read body from socket");
					} else {
						result.output = output;
						result.error = Errors.SUCCESS;
					}
				}
			} else {
				SLogger.e(TAG, "cant read header from socket");
				result.error = Errors.IO_ERROR;
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
			result.error = Errors.IO_ERROR;
		} finally {
		}
		
		return result;
	}
	
	@Override
	public int compareTo(NSClient client) {
		// TODO Auto-generated method stub
		
		if (this.id < client.id)
			return -1;
		
		if (this.id == client.id)
			return 0;
		
		if (this.id > client.id)
			return 1;
		
		return 0;
	}
	
    public static void main(String[] args) throws Exception {
    	SLogger.start(false, "c:\\cryptim_debug\\NSClient.log.txt", null);
		SLogger.i(TAG, "Client starting ...");
    	
		Security.addProvider(new BouncyCastleProvider());
		
		NSClient client = new NSClient("0.0.0.0", 8080, "c:\\cryptim_debug\\client.bks", "1q2w3e");
    	client.connect();
    	
    	IRealClock clock = new JRealClock();
    	for (int i = 0; i < 100; i++) {
    		clock.start();
    		byte[] input = new byte[1024*1024];
    		NSClientResult result = client.sendReceive(input);
    		if (result.error != Errors.SUCCESS)
    			System.out.println("error=" + result.error);
    		else
    			System.out.println("time=" + clock.elapsedTime() + " output.length=" + result.output.length);
    	}
    	
    	client.close();
    }

}
