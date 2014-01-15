package com.cserver.server;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import com.cserver.shared.SLogger;

public class TextEncoder {
	private static final String TAG = "TextEncoder";

	public static String encode(String s) {
		String encodedS = null;
		try {
			encodedS = URLEncoder.encode(s, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (encodedS != null)
			return encodedS.replace("*", "_MULTIPLY_");
		
		return null;
	}
}
