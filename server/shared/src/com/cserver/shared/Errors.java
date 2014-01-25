package com.cserver.shared;

import java.util.HashMap;
import java.util.Map;

public class Errors {
	public static Map<Integer, String> errorsMap = new HashMap<Integer, String>();

	public static final int SUCCESS = 0;
	public static final int ACCOUNT_ALREADY_REGISTRED = 1;
	public static final int ACCOUNT_LOGIN_OR_PASSWORD_INVALID = 2;
	public static final int AUTH_FAILURE = 3;
	public static final int SESSION_INVALID = 4;
	public static final int ACCOUNT_INVALID = 5;
	public static final int INVALID_REQUEST_TYPE = 6;
	public static final int INVALID_REQUEST_PARAMETERS = 7;
	public static final int INVALID_REQUEST_ID = 8;
	public static final int INVALID_HOST = 9;
	public static final int IO_ERROR = 10;
	public static final int UNSUCCESSFUL = 11;
	public static final int IOREQS_IS_ZERO = 12;
	public static final int SIGNIN_REQUIRED = 13;
	public static final int INTERNAL_SERVER_ERROR = 14;
	public static final int PURCHASE_DATA_SIGN_VERIFICATION_FAILED = 15;
	public static final int PURCHASE_NOT_FOUND = 16;
	public static final int NOTHING_WAS_FOUND = 17;
	public static final int EXPORT_DATA_NOT_FOUND = 18;
	public static final int SSL_REQUIRED = 19;
	public static final int SESSION_REQUIRED = 20;
	public static final int SERVER_NO_RESPONSE = 21;
	public static final int SERVER_HTTP_ERROR = 22;
	public static final int OBJECT_ALREADY_EXISTS = 23;
	public static final int OBJECT_NOT_FOUND = 24;
	public static final int ACCESS_DENIED = 25;
	public static final int AES_KEY_ENCRYPT_FAILED = 26;
	public static final int MSG_BODY_HASH_FAILED = 27;
	public static final int MSG_BODY_RSA_SIGN_FAILED = 28;
	public static final int MSG_BODY_AES_ENCRYPT_FAILED = 29;
	public static final int MSG_ENCRYPTED_BLOCK_SIZE_INVALID = 30;
	public static final int MSG_ENCRYPTED_BLOCK_FIELDS_INVALID = 31;
	public static final int MSG_ENCRYPTED_BLOCK_FIELDS_SIZE_INVALID = 32;
	public static final int AES_KEY_DECRYPT_FAILED = 33;
	public static final int AES_MSG_DECRYPT_FAILED = 34;
	public static final int DECRYPTED_MSG_SIZE_INVALID = 35;
	public static final int DECRYPTED_MSG_SIGN_SIZE_INVALID = 36;
	public static final int DECRYPTED_MSG_SIGN_FIELDS_INVALID = 37;
	public static final int CALC_MSG_BODY_HASH_FAILED = 38;
	public static final int MSG_UNPACK_FAILED = 39;
	public static final int MSG_ENC_KEY_ID_INCORRECT = 40;
	public static final int MSG_SIGN_INVALID = 41;
	public static final int URL_NOT_PARSED = 42;
	public static final int URL_CONNECTION_IO_EXCEPTION = 42;
	public static final int URL_CONNECTION_SOCKET_EXCEPTION = 43;
	public static final int URL_CONNECTION_EMPTY_OUTPUT = 44;
	public static final int CAPTCHA_NOT_FOUND = 45;
	public static final int CAPTCHA_OWNER_INVALID = 46;
	public static final int CAPTCHA_ANSWER_INVALID = 47;
	public static final int CLIENT_ENCRYPTION_SESSION_NOT_FOUND = 48;
	public static final int CLIENT_ENCRYPTION_SESSION_ALREADY_EXISTS = 49;
	public static final int CLIENT_CONNECTION_ERROR = 50;
	public static final int ACCOUNT_NOT_ACTIVE = 51;
	public static final int STRING_ENCODING_ERROR = 52;
	public static final int BAD_REQUEST_FORMAT = 53;
	
	public static void load() {
		errorsMap.put(SUCCESS, "success");
		errorsMap.put(ACCOUNT_ALREADY_REGISTRED, "This account already registred");
		errorsMap.put(ACCOUNT_LOGIN_OR_PASSWORD_INVALID, "An incorrect user name or password.");
		errorsMap.put(AUTH_FAILURE, "An incorrect user name or password");
		errorsMap.put(SESSION_INVALID, "session is invalid");
		errorsMap.put(ACCOUNT_INVALID, "account is not valid");
		errorsMap.put(INVALID_REQUEST_TYPE, "invalid request type");
		errorsMap.put(INVALID_REQUEST_PARAMETERS, "invalid request parameters");
		errorsMap.put(INVALID_REQUEST_ID, "invalid request id");
		errorsMap.put(INVALID_HOST, "invalid server host");
		errorsMap.put(IO_ERROR, "i/o error");
		errorsMap.put(UNSUCCESSFUL, "unsuccessful");
		errorsMap.put(IOREQS_IS_ZERO, "no requests available for current user");
		errorsMap.put(SIGNIN_REQUIRED, "account signin required to execute this operation");
		errorsMap.put(INTERNAL_SERVER_ERROR, "internal server error");
		errorsMap.put(PURCHASE_DATA_SIGN_VERIFICATION_FAILED, "purchase data verification by signature failed");
		errorsMap.put(PURCHASE_NOT_FOUND, "purchase not found");
		errorsMap.put(NOTHING_WAS_FOUND, "nothing was found");
		errorsMap.put(EXPORT_DATA_NOT_FOUND, "export data not found");
		errorsMap.put(SSL_REQUIRED, "ssl connection is required to perform request");
		errorsMap.put(SESSION_REQUIRED, "valid user session is required to perform request");
		errorsMap.put(SERVER_NO_RESPONSE, "server didn't send response");
		errorsMap.put(SERVER_HTTP_ERROR, "server communication http error");
		errorsMap.put(OBJECT_ALREADY_EXISTS, "object with such name already exists");
		errorsMap.put(OBJECT_NOT_FOUND, "object with such name not found");
		errorsMap.put(ACCESS_DENIED, "access denied");
		errorsMap.put(AES_KEY_ENCRYPT_FAILED, "aes key encryption failed");
		errorsMap.put(MSG_BODY_HASH_FAILED, "body hash calculation failed");
		errorsMap.put(MSG_BODY_RSA_SIGN_FAILED, "rsa sign failed");
		errorsMap.put(MSG_BODY_AES_ENCRYPT_FAILED, "body encryption by aes failed");
		errorsMap.put(MSG_ENCRYPTED_BLOCK_SIZE_INVALID, "encrypted block size is invalid");
		errorsMap.put(MSG_ENCRYPTED_BLOCK_FIELDS_INVALID, "encrypted block fields values are invalid");
		errorsMap.put(MSG_ENCRYPTED_BLOCK_FIELDS_SIZE_INVALID, "encrypted block fields sizes are invalid");
		errorsMap.put(AES_KEY_DECRYPT_FAILED, "aes key decryption failed");
		errorsMap.put(AES_MSG_DECRYPT_FAILED, "message decryption by aes failed");
		errorsMap.put(DECRYPTED_MSG_SIZE_INVALID, "decrypted message size is invalid");
		errorsMap.put(DECRYPTED_MSG_SIGN_SIZE_INVALID, "decrypted message sign size is invalid");
		errorsMap.put(DECRYPTED_MSG_SIGN_FIELDS_INVALID, "decrypted message sign fields are invalid");
		errorsMap.put(CALC_MSG_BODY_HASH_FAILED, "msg body hash calculation failed");
		errorsMap.put(MSG_UNPACK_FAILED, "msg unpacking failed");
		errorsMap.put(MSG_ENC_KEY_ID_INCORRECT, "msg encryption key id is incorrect");
		errorsMap.put(MSG_SIGN_INVALID, "msg sign is invalid");
		errorsMap.put(URL_NOT_PARSED, "server url was not parsed");
		errorsMap.put(URL_CONNECTION_IO_EXCEPTION, "i/o exception occured during connection");
		errorsMap.put(URL_CONNECTION_SOCKET_EXCEPTION, "socket exception occured during connection");
		errorsMap.put(URL_CONNECTION_EMPTY_OUTPUT, "connection received output is empty");
		errorsMap.put(CAPTCHA_NOT_FOUND, "captcha not found on server");
		errorsMap.put(CAPTCHA_OWNER_INVALID, "captcha owner is invalid");
		errorsMap.put(CAPTCHA_ANSWER_INVALID, "captcha answer is invalid");
		errorsMap.put(CLIENT_ENCRYPTION_SESSION_NOT_FOUND, "client encryption session not found");
		errorsMap.put(CLIENT_ENCRYPTION_SESSION_ALREADY_EXISTS, "client encryption session already exists");
		errorsMap.put(CLIENT_CONNECTION_ERROR, "client connection error");
		errorsMap.put(ACCOUNT_NOT_ACTIVE, "account is not active");
		errorsMap.put(STRING_ENCODING_ERROR, "string encoding error");
		errorsMap.put(BAD_REQUEST_FORMAT, "bad request format");
	}
	
	static {
		load();
	}
	
	public static String success() {	
		return errorsMap.get(SUCCESS);
	}
	
	public static String get(int value) {
		String errorDesc = errorsMap.get(value);
		if (errorDesc != null) {
			return errorDesc;
		} else {
			return "Error is " + value;
		}
	}

}
