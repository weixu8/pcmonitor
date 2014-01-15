package com.cserver.shared;

public class CaptchaResult {
	public int error = Errors.UNSUCCESSFUL;
	
	public String captchaId = null;
	public String captchaAnswer = null;
	public byte[] captchaBytes = null;
	
	public CaptchaResult(int error) {
		this.error = error;
	}
}
