package com.cserver.server;

import java.io.UnsupportedEncodingException;
import java.util.Map;

import com.cserver.shared.INSServerHandler;
import com.cserver.shared.Json;
import com.cserver.shared.SLogger;

public class CServerHandler implements INSServerHandler {

	private static final String TAG = "ServerHandleRequest";
	
	@Override
	public byte[] handle(byte[] input) {
		// TODO Auto-generated method stub
		
		//SLogger.d(TAG, "handle:input=" + Utils.bytesToHex(input));
		//JRealClock clock = new JRealClock();
		//clock.start();
		String inputS = null;
		try {
			inputS = new String(input, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (inputS == null) {
			SLogger.e(TAG, "no input request decoded");
			return null;
		}
		SLogger.d(TAG, "inputS=" + inputS);
		
		ClientRequest request = new ClientRequest();
		request.parseMap(Json.stringToMap(inputS));
		ClientRequest response = handleRequest(request);
		if (response == null) {
			SLogger.e(TAG, "no response");
			return null;
		}
		
		String outputS = Json.mapToString(response.toMap());
		SLogger.d(TAG, "outputS=" + inputS);
		byte[] output = null;
		try {
			output = outputS.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		return output; 
	}


	private ClientRequest handleRequest(ClientRequest request) {
		// TODO Auto-generated method stub
		ClientRequest response = null;
		
		switch (request.type) {
			case ClientRequest.TYPE_ECHO:
				response = handleEcho(request);
				break;
			case ClientRequest.TYPE_KEYBRD:
				response = handleKeyBrd(request);
				break;
			default:
				SLogger.e(TAG, "unsupported request type=" + request.type);
				response = new ClientRequest();
				response.status = ClientRequest.STATUS_ERROR_NOT_SUPPORTED;
				break;
		}
		
		return response;
	}


	private ClientRequest handleEcho(ClientRequest request) {
		// TODO Auto-generated method stub
		ClientRequest response = ClientRequest.clone(request);
		response.status = ClientRequest.STATUS_SUCCESS;
		
		return response;
	}
	
	private ClientRequest handleKeyBrd(ClientRequest request) {
		// TODO Auto-generated method stub
		ClientRequest response = ClientRequest.clone(request);
		response.status = ClientRequest.STATUS_SUCCESS;
		
		String events = null;
		try {
			events = new String(request.data, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (events != null) {
			Map<String, String> map = Json.stringToMap(events);
			for (String key : map.keySet()) {
				SLogger.d(TAG, "handleKeyBrd:key=" + key + " value=" + map.get(key));
			}
		}
		
		return response;
	}
}
	
