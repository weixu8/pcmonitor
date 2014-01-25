package com.cserver.shared;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class MessageCrypt {	

	private static final String TAG = "MessageCrypt";
	public static volatile boolean debug = false;
	
	public static void init(boolean isDebug) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		debug = isDebug;
	}
	
	public static byte[] rsaEncrypt(Key key, byte [] data) {
		byte[] encrypted = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			encrypted = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (NoSuchPaddingException e) {
			SLogger.exception(TAG, e);
		} catch (InvalidKeyException e) {
			SLogger.exception(TAG, e);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (Exception e) {
			SLogger.exception(TAG, e);
		}
		
		return encrypted;
	}
	
	public static byte[] rsaDecrypt(Key key, byte [] data) {
		byte[] plain = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
			cipher.init(Cipher.DECRYPT_MODE, key);
			plain = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (NoSuchPaddingException e) {
			SLogger.exception(TAG, e);
		} catch (InvalidKeyException e) {
			SLogger.exception(TAG, e);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (Exception e) {
			SLogger.exception(TAG, e);
		}
		
		
		return plain;
	}
	
	public static byte[] sha256(byte[] data) {
		byte []hash = null;
		try {
			MessageDigest md = null;
			md = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);
	        md.update(data);
	        hash = md.digest();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (Exception e) {
			SLogger.exception(TAG, e);
		} finally {
			
		}
		
		return hash;
	}
	
	public static byte[] aesEncrypt(byte[] key, byte[] data, byte[] iv) {
		byte []encrypted = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
			cipher.init( Cipher.ENCRYPT_MODE,  new SecretKeySpec(key, "AES"),  new IvParameterSpec(iv));
			encrypted = cipher.doFinal(data);
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}  catch (Exception e) {
			SLogger.exception(TAG, e);
		} finally {
			
		}
		return encrypted;
	}
	
	public static byte[] aesDecrypt(byte[] key, byte[] data, byte[] iv) {
		byte []plain = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
			cipher.init( Cipher.DECRYPT_MODE,  new SecretKeySpec(key, "AES"),  new IvParameterSpec(iv));
			plain = cipher.doFinal(data);
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}  catch (Exception e) {
			SLogger.exception(TAG, e);
		} finally {
			
		}
		return plain;
	}
	
	public static MessageCryptResult encryptMessage(String privKeyS, long privKeyId, Message msg, MessageCryptResolver resolver, IRealClock clock) {	
	
		PublicKey dstPubKey = null;
		PrivateKey privKey = null;
		MessageCryptResult result = new MessageCryptResult();
		
	
		if (debug) {
			SLogger.d(TAG, "encryptMessage:privKeyS=" + privKeyS);
			SLogger.d(TAG, "encryptMessage:privKeyId=" + privKeyId);
			SLogger.d(TAG, "encryptMessage:msg.id=" + msg.id);
			SLogger.d(TAG, "encryptMessage:msg.from=" + msg.from);
			SLogger.d(TAG, "encryptMessage:msg.peer=" + msg.peer);	
		}
		
		if (clock != null)
			clock.start();
		
		KeyQuery queryResult = resolver.getUserCurrentPubKey(msg.peer);
		if (clock != null)
			SLogger.d(TAG, "encryptMessage:getUserCurrentPubKey time=" + clock.elapsedTime());
		
		if (queryResult.error != Errors.SUCCESS) {
			if (debug)
				SLogger.e(TAG, "encryptMessage:getCurrentPubKey error= " + queryResult.error);
			
			result.error = queryResult.error;
			return result;
		}
		

		
		if (clock != null)
			clock.start();
		dstPubKey = JsonHelper.stringToPublicKey(queryResult.publicKey);
		if (clock != null)
			SLogger.d(TAG, "encryptMessage:Json.stringToPublicKey time=" + clock.elapsedTime());
		
		if (clock != null)
			clock.start();
		
		privKey = JsonHelper.stringToPrivateKey(privKeyS);
		if (clock != null)
			SLogger.d(TAG, "encryptMessage:Json.stringToPrivateKey time=" + clock.elapsedTime());
		
		msg.encKeyId = queryResult.keyId;
		msg.signKeyId = privKeyId;
		if (debug) {
			SLogger.d(TAG, "encryptMessage:msg.encKeyId=" + msg.encKeyId);
			SLogger.d(TAG, "encryptMessage:msg.signKeyId=" + msg.signKeyId);
			SLogger.d(TAG, "encryptMessage:pubKey=" + JsonHelper.publicKeyToString(dstPubKey));
		}
		
		if (clock != null)
			clock.start();
		
		byte []aesKey = new byte[32];
		SecureRandom rng = new SecureRandom();
		rng.nextBytes(aesKey);
		
		if (clock != null)
			SLogger.d(TAG, "encryptMessage:gen random AES key time=" + clock.elapsedTime());
		
		if (debug) {
			SLogger.d(TAG, "encryptMessage:aesKey=" + Base64.encode(aesKey));
		}
		
		if (clock != null)
			clock.start();
		
		byte[] encryptedAesKey = rsaEncrypt(dstPubKey, aesKey);
		
		if (clock != null)
			SLogger.d(TAG, "encryptMessage:rsaEncrypt AES key time=" + clock.elapsedTime());
		
		if (encryptedAesKey == null) {
			if (debug)
				SLogger.e(TAG, "encryptMessage:encryptedAesKey is null");
			result.error = Errors.AES_KEY_ENCRYPT_FAILED;
			return result;
		}
		if (clock != null)
			clock.start();
		byte body[] = msg.toBytes();
		
		if (clock != null)
			SLogger.d(TAG, "encryptMessage:msg.toBytes() time=" + clock.elapsedTime());
		
		if (clock != null)
			clock.start();
        byte bodyHash[] = sha256(body);
		if (clock != null)
			SLogger.d(TAG, "encryptMessage:sha256(body time=" + clock.elapsedTime());
		
        if (bodyHash == null) {
        	if (debug)
        		SLogger.e(TAG, "encryptMessage:bodyHash is null");
			result.error = Errors.MSG_BODY_HASH_FAILED;
        	return result;
        }
        
        if (debug) {
        	SLogger.d(TAG, "encryptMessage:body=" + Base64.encode(body));
        	SLogger.d(TAG, "encryptMessage:bodyHash=" + Base64.encode(bodyHash));
        }
        
		if (clock != null)
			clock.start();
			
        byte bodySign[] = rsaEncrypt(privKey, bodyHash);
		if (clock != null)
			SLogger.d(TAG, "encryptMessage:rsaEncrypt(bodyHash) time=" + clock.elapsedTime());
		
        if (bodySign == null) {
        	if (debug)
        		SLogger.e(TAG, "encryptMessage:bodySign is null");
			result.error = Errors.MSG_BODY_RSA_SIGN_FAILED;
        	return result;
        }
        
        if (debug) {
        	SLogger.d(TAG, "encryptMessage:bodySign=" + Base64.encode(bodySign));
        }
        
        ByteBuffer bb = ByteBuffer.allocate(body.length + bodySign.length + 8);
        
        bb.putInt(bodySign.length);
        bb.putInt(body.length);
        
        bb.put(bodySign);
        bb.put(body);
        
        byte[] iv = new byte[16];
		rng = new SecureRandom();
		rng.nextBytes(iv);
		
		if (clock != null)
			clock.start();
		
        byte[] encryptedData = aesEncrypt(aesKey, bb.array(), iv);
		if (clock != null)
			SLogger.d(TAG, "encryptMessage:aesEncrypt(body) time=" + clock.elapsedTime());
		
        if (encryptedData == null) {
        	if (debug)
        		SLogger.e(TAG, "encryptMessage:encryptedData is null");
			result.error = Errors.MSG_BODY_AES_ENCRYPT_FAILED;
        	return result;
        }

        
        if (debug) {
        	SLogger.d(TAG, "encryptMessage:plainData=" + Base64.encode(bb.array()));
        	SLogger.d(TAG, "encryptMessage:aesEncryptedData=" + Base64.encode(encryptedData));
        	SLogger.d(TAG, "encryptMessage:iv=" + Base64.encode(iv));
        }
        
		if (clock != null)
			clock.start();
		
        ByteBuffer bbResult = ByteBuffer.allocate(encryptedData.length + encryptedAesKey.length + iv.length + 12);
        
        bbResult.putInt(encryptedData.length);
        bbResult.putInt(encryptedAesKey.length);
        bbResult.putInt(iv.length);

        bbResult.put(encryptedData);
        bbResult.put(encryptedAesKey);
        bbResult.put(iv);
        
        result.encrypted = bbResult.array();
        result.error = Errors.SUCCESS;
        result.encKeyId = msg.encKeyId;
        
        if (debug) {
        	SLogger.d(TAG, "encryptMessage:result.encKeyId=" + result.encKeyId);
        }
        
		if (clock != null)
			SLogger.d(TAG, "encryptMessage:result buffer fill time=" + clock.elapsedTime());
		
        return result;
	}
	
	
	public static long getRndLong() {
		byte []longBytes = new byte[8];
		long result = -1;
		
		for (int i = 0; i < 100; i++) {
			SecureRandom rng = new SecureRandom();
			rng.nextBytes(longBytes);
		
			ByteBuffer bf = ByteBuffer.allocate(8);
			bf.put(longBytes);
			bf.position(0);
			
			result = bf.getLong();
			if ((result != 0) && (result != -1))
				break;
		}
		
		if (debug) {
			SLogger.d(TAG, "getRndLong=" + result);
		}
		
		return result;
	}
	
	public static KeyPair genKeys() {
	    KeyPairGenerator keyGen = null;
	    KeyPair kp = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		    keyGen.initialize(2048);
		    kp = keyGen.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (Exception e) {
			SLogger.exception(TAG, e);
		}
		
		return kp;
	}
	
	public static MessageCryptResult decryptMessage(String privKeyS, long privKeyId, byte[] msgBlock, MessageCryptResolver resolver, IRealClock clock) {
		
		MessageCryptResult result = new MessageCryptResult();
		
		PrivateKey privKey = JsonHelper.stringToPrivateKey(privKeyS);

		if (debug) {
			SLogger.d(TAG, "decryptMessage:privKey" + privKeyS);
			SLogger.d(TAG, "decryptMessage:privKeyId" + privKeyId);
			SLogger.d(TAG, "decryptMessage:msgBlock=" + Base64.encode(msgBlock));
		}
		
		if (msgBlock.length <= 12) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:msgBlock.length =" + msgBlock.length + " is invalid");
			
			result.error = Errors.MSG_ENCRYPTED_BLOCK_SIZE_INVALID;
			return result;
		}
		
		ByteBuffer bb = ByteBuffer.wrap(msgBlock);
		
		int dataLength = bb.getInt();
		int keyLength = bb.getInt();
		int ivLength = bb.getInt();
		
		if ((dataLength == 0) || (keyLength == 0) || (ivLength == 0)) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:dataLength=" + dataLength + " keyLength=" + keyLength + " ivLength=" + ivLength);
			
			result.error = Errors.MSG_ENCRYPTED_BLOCK_FIELDS_INVALID;
			return result;
		}
		
		if ((dataLength + keyLength + ivLength + 12) != msgBlock.length) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:dataLength=" + dataLength + " keyLength=" + keyLength + " ivLength=" + ivLength + " msgBlock.length=" + msgBlock.length);
			
			result.error = Errors.MSG_ENCRYPTED_BLOCK_FIELDS_SIZE_INVALID;
			return result;
		}
		
		byte[] encryptedData = new byte[dataLength];
		byte[] encryptedAesKey = new byte[keyLength];
		byte[] iv = new byte[ivLength];
		
		bb.get(encryptedData);
		bb.get(encryptedAesKey);
		bb.get(iv);
		
		if (debug) {
			SLogger.d(TAG, "decryptMessage:encryptedData=" + Base64.encode(encryptedData));
			SLogger.d(TAG, "decryptMessage:encryptedAesKey=" + Base64.encode(encryptedAesKey));
			SLogger.d(TAG, "decryptMessage:iv=" + Base64.encode(iv));
		}
		
		byte[] aesKey = rsaDecrypt(privKey, encryptedAesKey);
		if (aesKey == null) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:aesKey=null");
			
			result.error = Errors.AES_KEY_DECRYPT_FAILED;
			return result;
		}
		
		if (debug) {
			SLogger.d(TAG, "decryptMessage:aesKey.size=" + aesKey.length + " aesKey=" + Base64.encode(aesKey));
		}
		
//		System.out.println("aes_key=" + new String(aesKey));
		byte[] plainData = aesDecrypt(aesKey, encryptedData, iv);
		if (plainData == null) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:plainData=null");
			result.error = Errors.AES_MSG_DECRYPT_FAILED;
			return result;
		}
		
		if (debug) {
			SLogger.d(TAG, "decryptMessage:plainData=" + Base64.encode(plainData));
		}
		
		if (plainData.length <= 8) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:plainData.length=" + plainData.length);
			result.error = Errors.DECRYPTED_MSG_SIZE_INVALID;
			return result;
		}
		
		bb = ByteBuffer.wrap(plainData);
		
		int bodySignLength = bb.getInt();
		int bodyLength = bb.getInt();
		
		if ((bodySignLength == 0) || (bodyLength == 0)) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:bodySignLength=" + bodySignLength + " bodyLength=" + bodyLength);
			
			result.error = Errors.DECRYPTED_MSG_SIGN_SIZE_INVALID;
			return result;
		}
		
		if ((bodyLength + bodySignLength + 8) != plainData.length) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:bodyLength=" + bodySignLength + " bodyLength=" + bodyLength + " plainData.length=" + plainData.length);
			result.error = Errors.DECRYPTED_MSG_SIGN_FIELDS_INVALID;
			return result;
		}
		
		byte[] bodySign = new byte[bodySignLength];		
		byte[] body = new byte[bodyLength];
		
		bb.get(bodySign);
		bb.get(body);
		if (debug) {
			SLogger.d(TAG, "decryptMessage:body=" + Base64.encode(body));
			SLogger.d(TAG, "decryptMessage:bodySign=" + Base64.encode(bodySign));
		}
		
		byte[] bodyHash = sha256(body);
		if (bodyHash == null) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:bodyHash=null");
			result.error = Errors.CALC_MSG_BODY_HASH_FAILED;
			return result;
		}
		
		if (debug) {
			SLogger.d(TAG, "decryptMessage:bodyHash=" + Base64.encode(bodyHash));
		}
		
		Message msg = new Message();
		if (!msg.parseBytes(body)) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:msg not unpacked");
			result.error = Errors.MSG_UNPACK_FAILED;
			return result;
		}
		
		if (debug) {
			SLogger.d(TAG, "decryptMessage:msg.id=" + msg.id);
			SLogger.d(TAG, "decryptMessage:msg.encKeyId=" + msg.encKeyId);
			SLogger.d(TAG, "decryptMessage:msg.signKeyId=" + msg.signKeyId);
			SLogger.d(TAG, "decryptMessage:msg.from=" + msg.from);
			SLogger.d(TAG, "decryptMessage:msg.peer=" + msg.peer);	
		}
		
		if (privKeyId != msg.encKeyId) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:msg enc key id is wrong");
			result.error = Errors.MSG_ENC_KEY_ID_INCORRECT;
			return result;
		}
		
		KeyQuery queryResult = resolver.getPubKeyById(msg.from, msg.signKeyId);
		if (queryResult.error != Errors.SUCCESS) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:getPubKeyById error=" + queryResult.error);
			result.error = queryResult.error;
			return result;			
		}
		
		PublicKey signKey = JsonHelper.stringToPublicKey(queryResult.publicKey);
		
		byte[] plainBodyHash = rsaDecrypt(signKey, bodySign);
		
		if (debug) {
			SLogger.d(TAG, "decryptMessage:signKey=" + queryResult.publicKey);
			SLogger.d(TAG, "decryptMessage:bodySign=" + Base64.encode(bodySign));
			SLogger.d(TAG, "decryptMessage:plainBodyHash=" + Base64.encode(plainBodyHash));
			SLogger.d(TAG, "decryptMessage:bodyHash=" + Base64.encode(bodyHash));
		}
		
		if (!Arrays.equals(plainBodyHash, bodyHash)) {
			if (debug)
				SLogger.e(TAG, "decryptMessage:plainBodyHash != bodyHash");
			result.error = Errors.MSG_SIGN_INVALID;
			return result;
		}
		
		result.msg = msg;
		result.error = Errors.SUCCESS;
		
		      
		return result;
	}
	
	public static String encodePassword(String password, int numRounds) {
		byte [] digestb = null;
		try {
			digestb = password.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (digestb == null)
			return null;
		
		for (int i = 0; i < numRounds; i++) {
			MessageDigest mdb = null;
			try {
				mdb = MessageDigest.getInstance("SHA-512", BouncyCastleProvider.PROVIDER_NAME);
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}
			
			if (mdb == null) {
				return null;
			}
			
			digestb = mdb.digest(digestb);
			if (digestb == null)
				return null;
		}
		
		return JsonHelper.bytesToString(digestb);
	}

	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		SLogger.start(false, "c:\\log.txt", null);
		
		KeyPair kp = genKeys();
		System.out.println("public=" + JsonHelper.publicKeyToString(kp.getPublic()));
		System.out.println("private=" + JsonHelper.privateKeyToString(kp.getPrivate()));
		
		/*
		KeyPair kp = genKeys();
		String message = "1234567890123456789012345678901212345678901234567890123456789012";
		
		for (int i = 0; i < 5; i++) {
			byte[] encrypted = null;
			try {
				byte [] plain = message.getBytes("UTF-8");
				System.out.println("plain=" + Json.bytesToString(plain) + " len=" + plain.length);
				encrypted = rsaEncrypt(kp.getPublic(), message.getBytes("UTF-8"));
				System.out.println("encrypted=" + Json.bytesToString(encrypted));
				byte[] decrypted = rsaDecrypt(kp.getPrivate(), encrypted);
				
				System.out.println("decrypted=" + new String(decrypted, "UTF-8"));
	
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}
		}
		*/
		for (int i = 1; i < 400; i++)
			System.out.println(encodePassword("1q2w3e", i));
		
		//System.out.println("decryptMessage:plainBodyHash=" + Base64.encode(plainBodyHash));
	}
}
