package com.cserver.shared;



public class ServerTalk {
	
	private static final String TAG = "ServerTalk";
	private static IConnectionEnv connEnv = null;
	private static ServerApi srvApi = null;
	private static NSClientPool clientPool = null;
	
	public static void init(IConnectionEnv connEnv_, IClientKeyStore ks) {
		connEnv = connEnv_;
		srvApi = new ServerApi(connEnv.getServerHost(), connEnv.isSSL(), ks);
	}

	public static void init2(IConnectionEnv connEnv_, int numChannels) {
		connEnv = connEnv_;
		clientPool = new NSClientPool(connEnv.getServerHost(), connEnv.getServerPort(), numChannels, connEnv.getKsPath(), connEnv.getKsPass());
		SLogger.d(TAG, "clientPool inited");
	}
	
	public static void pause() {
		if (clientPool != null) {
			clientPool.pause();
			SLogger.d(TAG, "clientPool paused");
		}
	}
	
	public static void resume() {
		if (clientPool != null) {
			clientPool.resume();
			SLogger.d(TAG, "clientPool resumed");
		}
	}
	
	public static SRequest call(SRequest request) {
		SRequest response = null;
		String session = connEnv.getSession();
		if (request.isSessionRequired()) {
			if (session == null) {
				LastError.set(Errors.SIGNIN_REQUIRED);
				request.setError(Errors.SIGNIN_REQUIRED);
				return request;
			}
		}
		
		request.setSession(session);

		response = srvApi.call(request);
			
		if (response == null) {
			SLogger.e(TAG, "no response");
			LastError.set(Errors.SERVER_NO_RESPONSE);
			request.setError(Errors.SERVER_NO_RESPONSE);
			return request;
		}
		
		return response;
	}
	
	public static SRequest call2(SRequest request) {
		SRequest response = null;
		String session = connEnv.getSession();
		if (request.isSessionRequired()) {
			if (session == null) {
				LastError.set(Errors.SIGNIN_REQUIRED);
				request.setError(Errors.SIGNIN_REQUIRED);
				return request;
			}
		}
		
		request.setSession(session);
		byte[] input = SRequest.requestToBytes(request);
		if (input == null) {
			LastError.set(Errors.BAD_REQUEST_FORMAT);
			return SRequest.getErrorRequest(Errors.BAD_REQUEST_FORMAT);
		}
		
		//SLogger.d(TAG, "call2:send input=" + Utils.bytesToHex(input));
		NSClientResult result = clientPool.sendReceive(input);
		if (result.error != Errors.SUCCESS) {
			SLogger.e(TAG, "sendReceive error=" + result.error);
			LastError.set(result.error);
			return SRequest.getErrorRequest(result.error);
		}
		
		if (result.output == null) {
			SLogger.e(TAG, "no response");
			LastError.set(Errors.SERVER_NO_RESPONSE);
			return SRequest.getErrorRequest(Errors.SERVER_NO_RESPONSE);
		}
		
		//SLogger.d(TAG, "call2:received output=" + Utils.bytesToHex(result.output));

		response = SRequest.requestFromBytes(result.output);
		if (response == null) {
			SLogger.e(TAG, "no response 2");
			LastError.set(Errors.STRING_ENCODING_ERROR);
			return SRequest.getErrorRequest(Errors.STRING_ENCODING_ERROR);
		}
		
		return response;
	}
}
