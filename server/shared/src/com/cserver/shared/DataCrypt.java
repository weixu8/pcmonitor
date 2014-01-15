package com.cserver.shared;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class DataCrypt {

	private static final String TAG = "DataCrypt";
	private static final int IV_LENGTH = 16;
	public static final int AES_KEY_LENGTH = 32;
	public static volatile boolean debug = false;
	
	static public byte[] genAesKey() {
		byte[] aesKey = new byte[AES_KEY_LENGTH];
        SecureRandom rng = new SecureRandom();
		rng.nextBytes(aesKey);
		return aesKey;
	}
	
	public static void init(boolean isDebug) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		debug = isDebug;
	}
	
	static public byte[] RsaEncryptData(long pubKeyId, long pubKeyOwner, 
			long signKeyId, long signKeyOwner, byte[] data, IKeyResolver keyResolver) {
		byte[] encrypted = null;
		try {
			byte dataHash[] = MessageCrypt.sha256(data);
			if (dataHash == null) {
				if (debug)
					SLogger.e(TAG, "RsaEncryptData:dataHash is null");
				return null;
			}
			
			PrivateKey signKey = keyResolver.getPrivateKey(signKeyOwner, signKeyId);
	        byte sign[] = MessageCrypt.rsaEncrypt(signKey, dataHash);
	        if (sign == null) {
	        	if (debug)
	        		SLogger.e(TAG, "RsaEncryptData:dataSign is null");
	        	return null;
	        }
			
	        PublicKey pubKey = keyResolver.getPublicKey(pubKeyOwner, pubKeyId);
			byte[] encryptedData = MessageCrypt.rsaEncrypt(pubKey, data);
	        if (encryptedData == null) {
	        	if (debug)
	        		SLogger.e(TAG, "RsaEncryptData:encryptedData is null");
	        	return null;
	        }
	        
	        ByteBuffer bb = ByteBuffer.allocate(encryptedData.length + sign.length + 2*4 + 4*8);
	        bb.putInt(encryptedData.length);
	        bb.putInt(sign.length);
	        
	        bb.putLong(pubKeyId);
	        bb.putLong(pubKeyOwner);
	        bb.putLong(signKeyId);
	        bb.putLong(signKeyOwner);
	        
	        bb.put(encryptedData);
	        bb.put(sign);
	        
	        encrypted = bb.array();
		} catch (Exception e) {
			SLogger.e(TAG, "RsaEncryptData:encryptData exception=" + e.toString());
			SLogger.exception(TAG, e);
		}
		
        return encrypted;
	}
	
	
	static public byte[] RsaDecryptData(byte[] encrypted, IKeyResolver keyResolver) {
		byte[] data = null;
		try {
			ByteBuffer bb = ByteBuffer.wrap(encrypted);
			int encryptedDataLength = bb.getInt();
			int signLength = bb.getInt();
			
			long pubKeyId = bb.getLong();
			long pubKeyOwner = bb.getLong();
			
			long signKeyId = bb.getLong();
			long signKeyOwner = bb.getLong();
			
			if (encryptedDataLength <= 0 || signLength <= 0) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:encrypted data length mismatch");
				return null;
			}		
			
			if ((encryptedDataLength + signLength + 2*4 + 4*8 ) != encrypted.length) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:encrypted data length mismatch");
				return null;
			}
			
			byte[] encryptedData = new byte[encryptedDataLength];
			bb.get(encryptedData);
			
			byte[] sign = new byte[signLength];
			bb.get(sign);
						
			PrivateKey privKey = keyResolver.getPrivateKey(pubKeyOwner, pubKeyId);
			if (privKey == null) {
				if (debug)
					SLogger.e(TAG, "Cant get private key for keyOwner=" + pubKeyOwner + " pubKeyId=" + pubKeyId);
	        	return null;	
			}
			
			data = MessageCrypt.rsaDecrypt(privKey, encryptedData);
			if (data == null) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:decryptData is null");
	        	return null;
			}
			
			PublicKey signKey = keyResolver.getPublicKey(signKeyOwner, signKeyId);
			if (signKey == null) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:not found key with id=" + signKeyId + " owner=" + signKeyOwner);
				return null;
			}
			
			byte dataHash[] = MessageCrypt.sha256(data);
			if (dataHash == null) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:dataHash is null");
				return null;
			}
			
			byte[] plainSign = MessageCrypt.rsaDecrypt(signKey, sign);
			if (plainSign == null) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:plainSign is null");
				return null;
			}

			if (!Arrays.equals(plainSign, dataHash)) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:data sign is not correct");
				return null;	
			}
						
		} catch (Exception e) {
			SLogger.e(TAG, "AesDecryptData:decryptData exception=" + e.toString());
			SLogger.exception(TAG, e);
		}
		
		return data;
	}
	
	static public byte[] AesEncryptData(byte[] aesKey, long signOwner, long signKeyId, 
			byte[] data, IKeyResolver keyResolver) {
		
		byte[] encrypted = null;
		try {
			if (aesKey.length != AES_KEY_LENGTH) {
				if (debug)
					SLogger.e(TAG, "AesEncryptData:aesKey length mistmatch");
				return null;
			}
			
			byte dataHash[] = MessageCrypt.sha256(data);
			if (dataHash == null) {
				if (debug)
					SLogger.e(TAG, "AesEncryptData:dataHash is null");
				return null;
			}
			
			PrivateKey signKey = keyResolver.getPrivateKey(signOwner, signKeyId);
	        byte sign[] = MessageCrypt.rsaEncrypt(signKey, dataHash);
	        if (sign == null) {
	        	if (debug)
	        		SLogger.e(TAG, "AesEncryptData:dataSign is null");
	        	return null;
	        }
			
	        ByteBuffer bb = ByteBuffer.allocate(sign.length + data.length + 2*4 + 2*8);
	        bb.putInt(sign.length);
	        bb.putInt(data.length);
	        bb.putLong(signKeyId);
	        bb.putLong(signOwner);
	        bb.put(sign);
	        bb.put(data);
			
	        byte dataToEncrypt[] = bb.array();
	        
			byte[] iv = new byte[IV_LENGTH];
	        SecureRandom rng = new SecureRandom();
			rng.nextBytes(iv);
						
			byte[] encryptedData = MessageCrypt.aesEncrypt(aesKey, dataToEncrypt, iv);
	        if (encryptedData == null) {
	        	if (debug)
	        		SLogger.e(TAG, "AesEncryptData:encryptedData is null");
	        	return null;
	        }
	        
	        bb = ByteBuffer.allocate(iv.length + encryptedData.length + 2*4);
	        bb.putInt(iv.length);
	        bb.putInt(encryptedData.length);
	        bb.put(iv);
	        bb.put(encryptedData);
	        encrypted = bb.array();
		} catch (Exception e) {
			SLogger.e(TAG, "AesEncryptData:encryptData exception=" + e.toString());
			SLogger.exception(TAG, e);
		}
		
        return encrypted;
	}
	
	static public byte[] AesDecryptData(byte[] aesKey, byte[] encrypted, IKeyResolver keyResolver) {
		byte[] data = null;
		try {
			ByteBuffer bb = ByteBuffer.wrap(encrypted);
			
			int ivLength = bb.getInt();
			int encryptedDataLength = bb.getInt();
			if (ivLength <= 0 || encryptedDataLength <= 0) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:encrypted data length mismatch");
				return null;
			}
			
			if (ivLength != IV_LENGTH) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:ivLength mismatch");
				return null;
			}
			
			if ((ivLength + encryptedDataLength + 2*4 ) != encrypted.length) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:encrypted data length mismatch");
				return null;
			}
			
			byte[] iv = new byte[ivLength];
			byte[] encryptedData = new byte[encryptedDataLength];
			
			bb.get(iv);
			bb.get(encryptedData);
			byte[] decrypted = MessageCrypt.aesDecrypt(aesKey, encryptedData, iv);
			if (decrypted == null) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:decryptData is null");
	        	return null;
			}
			
			bb = ByteBuffer.wrap(decrypted);
			int signLength = bb.getInt();
			int dataLength = bb.getInt();
			long signId = bb.getLong();
			long signOwner = bb.getLong();
			
			if (signLength <= 0 || dataLength <=0) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:decrypted data length mismatch");
				return null;
			}
			
			if ((signLength + dataLength + 2*4 + 2*8) != decrypted.length) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:decrypted data length mismatch");
				return null;
			}
			
			PublicKey signKey = keyResolver.getPublicKey(signOwner, signId);
			if (signKey == null) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:not found key with id=" + signId);
				return null;
			}
			
			byte[] sign = new byte[signLength];
			data = new byte[dataLength];
			
			bb.get(sign);
			bb.get(data);
			
			byte dataHash[] = MessageCrypt.sha256(data);
			if (dataHash == null) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:dataHash is null");
				return null;
			}
			
			byte[] plainSign = MessageCrypt.rsaDecrypt(signKey, sign);
			if (plainSign == null) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:plainSign is null");
				return null;
			}

			if (!Arrays.equals(plainSign, dataHash)) {
				if (debug)
					SLogger.e(TAG, "AesDecryptData:data sign is not correct");
				return null;	
			}
						
		} catch (Exception e) {
			SLogger.e(TAG, "AesDecryptData:decryptData exception=" + e.toString());
			SLogger.exception(TAG, e);
		}
		
		return data;
	}
	
}
