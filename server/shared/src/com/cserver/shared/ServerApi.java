package com.cserver.shared;


public class ServerApi {
	private static final String TAG = "ServerApi";
	private String host = null;
	private boolean https = false;
	private IClientKeyStore ks = null;
	
	public ServerApi(String host, boolean https, IClientKeyStore ks) {
		this.host = host;
		this.https = https;
		this.ks = ks;
	}
	
	public SRequest call(SRequest sRequest) {
		SRequest response = null;
		for (int i = 0; i < 5; i++) {
			response = callInternal(sRequest);
			if (response.getError() == Errors.CLIENT_CONNECTION_ERROR) {
				continue;
			} else {
				break;
			}
		}
		return response;
	}
	
	private SRequest callInternal(SRequest sRequest) {
		SRequest sResponse = new SRequest();
		sResponse.setError(Errors.INTERNAL_SERVER_ERROR);
		IClientKey client = null;	
		long clientId = -1;
		
		synchronized(ServerApi.class) {
		try {
			clientId = ks.getCurrentClient();
			if (clientId == -1) {
				clientId = ks.createClient();
				if (clientId == -1) {
					throw new ErrorException(Errors.INTERNAL_SERVER_ERROR, "client is not created");
				}
				
				client = ks.getClient(clientId);
				if (client == null) {
					throw new ErrorException(Errors.OBJECT_NOT_FOUND, "cant get client by id=" + clientId);
				}
				
				SERequest request = new SERequest();
				request.type = SERequest.TYPE_CLIENT_REGISTER;
				
				KeyQuery kq = client.getPublicKey();
				if (kq.error != Errors.SUCCESS) {
					throw new ErrorException(kq.error, "cant get client public key");
				}
				
				request.clientKeyId = kq.keyId;
				request.clientKey = kq.publicKey;
				
				request = callSE(request);
				if (request.error != Errors.SUCCESS) {
					throw new ErrorException(request.error, "callSE failed");
				}
				
				ks.setClientRemoteId(clientId, request.clientId);
				byte[] keyBytes = DataCrypt.RsaDecryptData(Json.stringToBytes(request.data), ks);
				if (keyBytes == null) {
					throw new ErrorException(Errors.UNSUCCESSFUL, "cant decode session key");
				}
				
				ks.setClientSessionKey(clientId, Json.bytesToString(keyBytes));
				ks.setCurrentClient(clientId);
			}
			
			client = ks.getClient(clientId);
			if (client == null) {
				throw new ErrorException(Errors.OBJECT_NOT_FOUND, "cant get client by id=" + clientId);
			}
			
			KeyQuery kqPubKey = client.getPublicKey();
			if (kqPubKey.error != Errors.SUCCESS) {
				throw new ErrorException(kqPubKey.error);
			}
			
			KeyQuery kqSessionKey = client.getSessionKey();
			if (kqSessionKey.error != Errors.SUCCESS) {
				throw new ErrorException(kqSessionKey.error);
			}
			
			SERequest request = new SERequest();
			request.type = SERequest.TYPE_CLIENT_DATA;
			request.clientId = client.getRemoteId();
			
			byte []sessionKey = Json.stringToBytes(kqSessionKey.sessionKey);

			String jsonRequest = Json.mapToString(sRequest.toMap());

			byte [] encryptedData = DataCrypt.AesEncryptData(sessionKey, client.getRemoteId(), 
					kqPubKey.keyId, jsonRequest.getBytes("UTF-8"), ks);
						
			request.data = Json.bytesToString(encryptedData);
			
			request = callSE(request);
			if (request.error != Errors.SUCCESS) {
				throw new ErrorException(request.error);
			}
			
			byte[] decrypted = DataCrypt.AesDecryptData(sessionKey, Json.stringToBytes(request.data), ks);
			
			sResponse.parseMap(Json.stringToMap(new String(decrypted, "UTF-8")));
			
			SLogger.i(TAG, "request " + sResponse.getType() + " completed with err=" + sResponse.getError());
			
		} catch (Exception e) {
			SLogger.exception(TAG, e);
			ks.setCurrentClient(-1);
			ks.deleteClient(clientId);
			
			sResponse.setError(Errors.CLIENT_CONNECTION_ERROR);
		}
		
		}
		return sResponse;
	}
	
	private SERequest callSE(SERequest request) {
		SERequest answer = new SERequest();
		try {
			HttpConnResult result = HttpConn.post(https, host, "/client/", Json.mapToString(request.toMap()));
			if (result.error != Errors.SUCCESS) {
				SLogger.e(TAG, "call error=" + result.error);
				answer.error = result.error;
				return answer;
			}
			
			answer.parseMap(Json.stringToMap(result.output));
			return answer;
		} catch (Exception e) {
			SLogger.e(TAG, "exception=" + e.toString());
			answer.error = Errors.INTERNAL_SERVER_ERROR;
		}
		return answer;
	}
	
	public static void main(String[] args) {
		 ServerApi srvApi = new ServerApi("127.0.0.1", false, null);
		 
		 for (int i = 0; i < 10; i++) {
			 SRequest request = new SRequest(SRequest.TYPE_ECHO);
			 SRequest response = null;
			 
			 long t1 = System.currentTimeMillis();
			 response = srvApi.call(request);
			 long t2 = System.currentTimeMillis();
			 
			 System.out.println("response error=" + response.getError() + " time=" + (t2 - t1) + " ms");
		 }
	 }
}
