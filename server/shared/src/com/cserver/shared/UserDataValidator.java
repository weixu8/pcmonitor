package com.cserver.shared;


public class UserDataValidator {
	private static String specialChars = "!@#$%^&*()_|+/-=";
	
    public static String validateLogin(String login) {
    	if (login.length() < 3)
    		return "login is too short, at least 3 characters required";
    	
    	if (!Character.isLetter(login.charAt(0))) 
    		return "login must start with letter character";
    	
    	for (int i = 1; i < login.length(); i++) {
    		if (!Character.isLetterOrDigit(login.charAt(i)))
    				return "login should contains only letters or digits";
    	}
    	
    	return null;
    }
    
    public static boolean isSpecialChar(char c) {
    	for (int i = 0; i < specialChars.length(); i++) {
    		if (c == specialChars.charAt(i))
    			return true;
    	}
    	return false;
    }
    
    public static String validatePass(String pass) {
    	if (pass.length() < 6)
    		return "password is too short, at least 6 characters required";

    	for (int i = 1; i < pass.length(); i++) {
    		if (Character.isLetterOrDigit(pass.charAt(i)))
    			continue;
    		if (isSpecialChar(pass.charAt(i)))
    			continue;
			return "password should contains only letters, digits or special characters " + specialChars;
    	}
    	
    	return null;
    }
    
    public static String validateEmail(String email) {
    	EmailValidator validator = new EmailValidator();
    	if (!validator.validate(email)) {
    		return "email is not valid";
    	}
    	
    	return null;
    }
    
}
