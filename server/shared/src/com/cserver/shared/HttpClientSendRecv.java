package com.cserver.shared;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;


class HttpRequestStatus {
	public HttpResponse response = null;
	public int status = -1;
}

public class HttpClientSendRecv {
	private static final String TAG = "HttpClientSendRecv";

	private static HttpRequestStatus send(String uri, SRequest request) {
		HttpRequestStatus status = new HttpRequestStatus();		
		try {        
		        HttpClient client = new DefaultHttpClient();
		        HttpPost post = new HttpPost();
		        post.setURI(new URI(uri));
		        List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
		        
		        nameValuePairs.add(new BasicNameValuePair("request", Json.mapToString(request.toMap())));
		        post.setEntity(new UrlEncodedFormEntity(nameValuePairs));

		        status.response = client.execute(post);
		        if (status.response != null)
		        	status.status = status.response.getStatusLine().getStatusCode();
		        
		        if (status.status != HttpStatus.SC_OK) {
		        	SLogger.e(TAG, "Http post on uri=" + uri + " status=" + status.status);
		        }
		} catch (URISyntaxException e) {
			SLogger.exception(TAG, e);
	    } catch (ClientProtocolException e) {
	        // TODO Auto-generated catch block
	    	SLogger.exception(TAG, e);
	    } catch (IOException e) {
	        // TODO Auto-generated catch block
	    	SLogger.exception(TAG, e);
	    }   
		
	    return status;
	}

	private static String convertStreamToString(InputStream inputStream) throws IOException {
	    if (inputStream != null) {
	        Writer writer = new StringWriter();
	
	        char[] buffer = new char[1024];
	        try {
	            Reader reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"),1024);
	            int n;
	            while ((n = reader.read(buffer)) != -1) {
	                writer.write(buffer, 0, n);
	            }
	        } finally {
	            inputStream.close();
	        }
	        return writer.toString();
	    } else {
	        return null;
	    }
	}
	
	public static SRequest sendRecv(String uri, SRequest request) {
		HttpRequestStatus status = send(uri, request);
		SRequest result = new SRequest();
		if (status.status != HttpStatus.SC_OK) {
			result.setError(Errors.SERVER_HTTP_ERROR);
			return result;
		}
		
		HttpResponse response = status.response;
		InputStream is = null;
		String output = null;
		try {
			is = response.getEntity().getContent();
			output = convertStreamToString(is);
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		} finally {
		}
		
		result.parseMap(Json.stringToMap(output));
		
		return result;
	}
}
