package com.cserver.shared;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class JsonHelper {
	private static final String TAG = "Json";
	private static Gson gson = new Gson();
	
	
	public static String stringArrToJson(String[] arr) {
		return gson.toJson(arr);
	}
	
	public static String[] jsonToStringArr(String json) {
		String[] arr = new Gson().fromJson(json, new TypeToken<String[]>(){}.getType());
		return arr;
	}
		
	public static String mapStringToStringArrToJson(Map<String, String[]> map) {
		return gson.toJson(map);
	}
	
	public static String mapLLToString(Map<Long, Long> map) {
		return gson.toJson(map);
	}
	
	public static Map<Long, Long> stringToLLMap(String json) {
		Map<Long, Long> map = new Gson().fromJson(json, new TypeToken<Map<Long,Long>>(){}.getType());
		return map;
	}
	
	public static String mapToString(Map<String, String> map) {
		return gson.toJson(map);
	}
	
	public static Map<String, String> stringToMap(String json) {
		Map<String, String> map = new Gson().fromJson(json, new TypeToken<Map<String,String>>(){}.getType());
		return map;
	}
	
	public static String longListToString(List<Long> list) {
		return gson.toJson(list);
	}
	
	public static List<Long> stringToLongList(String json) {
		List<Long> list = new Gson().fromJson(json, new TypeToken<List<Long>>(){}.getType());
		return list;
	}

	public static String stringListToString(List<String> list) {
		return gson.toJson(list);
	}
	
	public static List<String> stringToStringList(String json) {
		List<String> list = new Gson().fromJson(json, new TypeToken<List<String>>(){}.getType());
		return list;
	}
	
	public static String bytesListToString(List<byte []> list) {
		List<String> slist = new ArrayList<String>();
		for (byte [] b : list) {
			slist.add(Base64.encode(b));
		}
		
		return stringListToString(slist);
	}
	
	public static List<byte[]> stringToBytesList(String json) {
		List<String> slist = stringToStringList(json);
		
		List<byte []> blist = new ArrayList<byte []>();
		for (String s : slist) {
			try {
				blist.add(Base64.decode(s));
			} catch (Base64DecoderException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}
		}

		return blist;
	}
	
	public static String publicKeyToString(PublicKey pubKey) {
		return Base64.encode(pubKey.getEncoded());
	}
	
	public static PublicKey stringToPublicKey(String json) {
		byte pubKeyBytes[] = null;
		try {
			pubKeyBytes = Base64.decode(json);
		} catch (Base64DecoderException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (pubKeyBytes == null) {
			SLogger.d(TAG, "pubKeyBytes not decoded");
			return null;
		}
		
		PublicKey publicKey = null;
		try {
			publicKey = 
				    KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).generatePublic(new X509EncodedKeySpec(pubKeyBytes));
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (publicKey == null) {
			SLogger.e(TAG, "publicKey not extracted");
		}
		
		return publicKey;
	}
	
	public static String privateKeyToString(PrivateKey privKey) {
		return Base64.encode(privKey.getEncoded());
	}
	
	public static PrivateKey stringToPrivateKey(String json) {
		byte privKeyBytes[] = null;
		try {
			privKeyBytes = Base64.decode(json);
		} catch (Base64DecoderException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (privKeyBytes == null) {
			SLogger.d(TAG, "pubKeyBytes not decoded");
			return null;
		}
		
		PrivateKey privKey = null;
		try {
			privKey = 
				    KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).generatePrivate(new PKCS8EncodedKeySpec(privKeyBytes));
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (privKey == null) {
			SLogger.e(TAG, "publicKey not extracted");
		}
		
		return privKey;
	}
	
	public static byte[] stringToBytes(String string) {
		byte[] bytes = null;
		try {
			bytes = Base64.decode(string);
		} catch (Base64DecoderException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		return bytes;
	}
	
	public static String bytesToString(byte [] bytes) {
		return Base64.encode(bytes);
	}
	
	public static String messageInfoListToString(List<MessageInfo> msgs) {
		List<String> list = new ArrayList<String>();
		for (MessageInfo msg : msgs) {
			list.add(mapToString(msg.toMap()));
		}
		return stringListToString(list);
	}
	
	public static List<MessageInfo> stringToMessageInfoList(String json) {
		List<String> list = stringToStringList(json);
		List<MessageInfo> msgInfoList = new ArrayList<MessageInfo>();
		
		for (String s : list) {
			MessageInfo msg = new MessageInfo();
			msg.parseMap(stringToMap(s));
			msgInfoList.add(msg);
		}
		
		return msgInfoList;
	}
}
