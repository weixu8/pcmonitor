package com.cserver.shared;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.Charset;


public class HttpConn {
	private static final String TAG = "HttpConn";
	
	private static int HTTP_PORT = 80;
	private static int HTTPS_PORT = 443;
	
	public static void setHttpPort(int port) {
		HTTP_PORT = port;
	}
	
	public static void setHttpsPort(int port) {
		HTTPS_PORT = port;
	}
	
	public static StringBuffer readInputToString(InputStream in) {
		StringBuffer output = new StringBuffer();
		try {
			BufferedReader reader = new BufferedReader(new InputStreamReader(in));
			String line = null;
			while((line = reader.readLine())!=null){
				output.append(line);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} finally {
		} 
		
		return output;
	}
	
	public static URL getUrl(boolean https, String host, String uri) {
		URL url = null;
		try {
			
			url = new URL((https) ? "https" : "http", host, getPort(https), uri);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		return url;
	}

	public static HttpConnResult get(boolean https, String host, String uri) {
		HttpConnResult result = new HttpConnResult();
		URL url = getUrl(https, host, uri);
		if (url == null) {
			result.error = Errors.URL_NOT_PARSED;
			return result;
		}
		
		HttpURLConnection urlConnection = null;
		try {
			urlConnection = (HttpURLConnection)url.openConnection();
			urlConnection.setConnectTimeout(5000);
			urlConnection.setReadTimeout(5000);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
			result.error = Errors.URL_CONNECTION_IO_EXCEPTION;
		}
		
		if (urlConnection == null) {
			return result;
		}
		
		StringBuffer output = null;
		try {
			InputStream in = new BufferedInputStream(urlConnection.getInputStream());
			output = readInputToString(in);
			if (output == null) {
				result.error = Errors.URL_CONNECTION_EMPTY_OUTPUT;
			} else {
				result.output = output.toString();
				result.error = Errors.SUCCESS;
			}
		} catch (SocketTimeoutException e) {
			SLogger.exception(TAG, e);
			result.error = Errors.URL_CONNECTION_SOCKET_EXCEPTION;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
			result.error = Errors.URL_CONNECTION_IO_EXCEPTION;
		} finally {
			urlConnection.disconnect();
		} 

		return result;
	}
	
	private static int getPort(boolean https) {
		return (https) ? HTTPS_PORT : HTTP_PORT;
	}
	
	public static HttpConnResult post(boolean https, String host, String uri, String data) {
		HttpConnResult result = new HttpConnResult();
		
		URL url = getUrl(https, host, uri);
		if (url == null) {
			result.error = Errors.URL_NOT_PARSED;
			return result;
		}
		
		StringBuffer output = null;
		HttpURLConnection urlConnection = null;
		
		try {
			urlConnection = (HttpURLConnection) url.openConnection();
			urlConnection.setConnectTimeout(5000);
			urlConnection.setReadTimeout(5000);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
			result.error = Errors.URL_CONNECTION_IO_EXCEPTION;
		}
		
		if (urlConnection == null) {
			return result;
		}
		
		try {
			urlConnection.setDoOutput(true);
			
			byte[] rawData = data.getBytes(Charset.forName("UTF-8"));
			//urlConnection.setChunkedStreamingMode(rawData.length);

			OutputStream out = new BufferedOutputStream(urlConnection.getOutputStream());
			out.write(rawData);
			out.flush();
			out.close();
			InputStream in = new BufferedInputStream(urlConnection.getInputStream());
			output = readInputToString(in);
			if (output == null) {
				result.error = Errors.URL_CONNECTION_EMPTY_OUTPUT;
			} else {
				result.output = output.toString();
				result.error = Errors.SUCCESS;
			}
		} catch (SocketTimeoutException e) {
			SLogger.exception(TAG, e);
			result.error = Errors.URL_CONNECTION_SOCKET_EXCEPTION;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
			result.error = Errors.URL_CONNECTION_IO_EXCEPTION;
		} finally {
	    	urlConnection.disconnect();
	    }
		
		return result;
	 }
	
	 public static void main(String[] args) {
		 HttpConn.post(false, "127.0.0.1", "/api", "xuidata");
	 }
}
