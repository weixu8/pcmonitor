package com.cserver.shared;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SSLSocketLib {
	
	private static final String TAG = "SSLSocketLib";
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static SSLEngine createSSLEngine(String ksPath, String ksPass, String keyPass, String ksType) {
		SSLContext sc = null;
		SSLEngine engine = null;
		
	    try {
	       KeyStore ks = KeyStore.getInstance(ksType);
	       FileInputStream ksis = new FileInputStream(ksPath);
	       ks.load(ksis, ksPass.toCharArray());
	       KeyManagerFactory kmf = 
	       KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
	       kmf.init(ks, keyPass.toCharArray());
	       sc = SSLContext.getInstance("TLSv1.2");
	       sc.init(kmf.getKeyManagers(), null, null);
	       engine = sc.createSSLEngine();
	       engine.setUseClientMode(false);
	    } catch (Exception e) {
	    	SLogger.exception(TAG, e);
	    }
	    return engine;
	}
	
	public static ServerSocket createServerSocket(
			String keyStorePath, String keyStorePass, String keyPass, String host, int port)
	{
		ServerSocket socket = null;
	    try {
	       KeyStore ks = KeyStore.getInstance("BKS");
	       FileInputStream ksis = new FileInputStream(keyStorePath);
	       ks.load(ksis, keyStorePass.toCharArray());
	       KeyManagerFactory kmf = 
	       KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
	       kmf.init(ks, keyPass.toCharArray());
	       SSLContext sc = SSLContext.getInstance("TLSv1.2");
	       sc.init(kmf.getKeyManagers(), null, null);
	       SSLServerSocketFactory ssf = sc.getServerSocketFactory();
	       	       
	       socket = ssf.createServerSocket(port, 100000, InetAddress.getByName(host));
	    } catch (Exception e) {
	    	SLogger.exception(TAG, e);
	    }
	    
	    return socket;
    }
	
	public static Socket createClientSocketAndHandshake(
			String host, int port, String ksPath, String ksPass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyManagementException 
	{
	    Socket socket = null;
        KeyStore ks = KeyStore.getInstance("BKS");
	    ks.load(new FileInputStream(ksPath), ksPass.toCharArray());
	       
        SSLContext sc = SSLContext.getInstance("TLSv1.2");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        tmf.init(ks);
        sc.init(null, tmf.getTrustManagers(),null);
	    SSLSocketFactory ssf = sc.getSocketFactory();
	    		  
	    socket = ssf.createSocket(host, port);
	    SSLSocket sslSocket = (SSLSocket)socket;
	    sslSocket.startHandshake();

	    return socket;
	}
}
