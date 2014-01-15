package com.cserver.shared;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;


public class ClientSendRecv {
	private String host;
	private int port;
	private static final String TAG = "ClientSendRecv";
	private String keyStorePath = null;
	private String keyStorePass = null;
	
	public ClientSendRecv(String host, int port, String keyStorePath, String keyStorePass) {
		this.host = host;
		this.port = port;
		this.keyStorePath = keyStorePath;
		this.keyStorePass = keyStorePass;
	}

	public SRequest sendRecv(SRequest request) {
		GZIPInputStream gis = null;
		GZIPOutputStream gos = null;
		InputStream is = null;
		OutputStream os = null;
		
		SRequest response = null;

		Socket socket = null;
		try {
			if (keyStorePath == null) {
				socket = new Socket(InetAddress.getByName(this.host), this.port);
			} else {				
				socket = SSLSocketLib.createClientSocketAndHandshake(this.host, this.port, this.keyStorePath, this.keyStorePass);
			}
			
			os = socket.getOutputStream();
			gos = new GZIPOutputStream(os);
			
			SLogger.d(TAG, "before write");
			request.write(gos);
			SLogger.d(TAG,"after write");
			gos.finish();
			
			response = new SRequest();
			SLogger.d(TAG,"before read");
			is = socket.getInputStream();
			gis = new GZIPInputStream(is);
			response.read(gis);
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			LastError.set(Errors.INVALID_HOST);
			SLogger.exception(TAG, e);
			response = null;
		} catch (IOException e) {
			LastError.set(Errors.IO_ERROR);
			SLogger.exception(TAG, e);
			response = null;
		} catch (Exception e) {
			LastError.set(Errors.IO_ERROR);
			SLogger.exception(TAG, e);
			response = null;
		} finally {
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
		}
		
		if (response != null && !response.packetId.equals(request.packetId)) {
			SLogger.e(TAG,"responseid=" + response.packetId + " vs. requestid=" + request.packetId);
			LastError.set(Errors.INVALID_REQUEST_ID, "responseid=" + response.packetId + " vs. requestid=" + request.packetId);
			response = null;
		}
		
		if (response != null) {
			LastError.set(response.getError(), response.getErrorDetails());
			SLogger.i(TAG, "response error=" + response.getError() + " details=" + response.getErrorDetails());
		}
		
		return response;
	}
}
