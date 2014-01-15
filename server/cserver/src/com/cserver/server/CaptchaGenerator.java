package com.cserver.server;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;

import javax.imageio.ImageIO;

import nl.captcha.Captcha;
import nl.captcha.backgrounds.GradiatedBackgroundProducer;
import nl.captcha.gimpy.FishEyeGimpyRenderer;
import nl.captcha.noise.StraightLineNoiseProducer;
import nl.captcha.noise.CurvedLineNoiseProducer;
import nl.captcha.text.producer.TextProducer;
import nl.captcha.backgrounds.SquigglesBackgroundProducer;

import com.cserver.shared.FileOps;
import com.cserver.shared.SLogger;

class MyTextProducer implements TextProducer 
{
	private static final String textChars = "abcdefghijklmnopqrstuvwxyz0123456789";
	private static final int maxChars = 6;
	
	@Override
	public String getText() {
		// TODO Auto-generated method stub
		
		SecureRandom random = new SecureRandom();
	    byte rndBytes[] = new byte[maxChars];
	    random.nextBytes(rndBytes);
	    
	    String text = "";
	    
	    for (int i = 0; i < maxChars; i++) {
	    	text+= textChars.charAt((rndBytes[i] - Byte.MIN_VALUE)%textChars.length());
	    }
		
	    return text;
	}
}


public class CaptchaGenerator {

	private static final String TAG = "CaptchaGenerator";
	
	public static Captcha genCaptcha(int width, int height) {
		Captcha captcha = new Captcha.Builder(width, height)
		.addText(new MyTextProducer())
		.addBackground(new GradiatedBackgroundProducer())
		.addNoise(new CurvedLineNoiseProducer())
		.gimp(new FishEyeGimpyRenderer())
		.addBorder()
		.build(); 
	
		return captcha;
	}
	
	public static byte[] captchaToBytes(Captcha captcha) {
		byte []bytes = null;
		BufferedImage img = captcha.getImage();
		if (img != null) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			try {
				ImageIO.write(img, "png", baos);
				baos.flush();
				bytes = baos.toByteArray();
				baos.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				SLogger.exception(TAG, e);
			}
		}
		return bytes;
	}
	
	public static void main(String[] args) {
		SLogger.start(false, "c:\\log.txt", new PostLogger());
		Captcha captcha = genCaptcha(200, 50);
		
		if (captcha != null) {
			byte []bytes = captchaToBytes(captcha);
			FileOps.writeFileBinary(new File("c:\\captcha.png"), bytes);
			System.out.println("Answer= " + captcha.getAnswer());
		}
		
	}
}
