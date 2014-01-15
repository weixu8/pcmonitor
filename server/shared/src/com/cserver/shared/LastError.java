package com.cserver.shared;


public class LastError {

    private static final String TAG = "LastError";

	private static ThreadLocal<Integer> error = new ThreadLocal<Integer>() {
        protected Integer initialValue() {
            return Integer.valueOf(Errors.SUCCESS);
        }
    };
    
    private static ThreadLocal<String> errorDetails = new ThreadLocal<String>() {
        protected String initialValue() {
            return "Undefined";
        }
    };
    
    public static void set(int newError, String newErrorDetails) { 
    	SLogger.d(TAG, "set error=" + newError + " details=" + newErrorDetails);
    	error.set(newError);
    	errorDetails.set(newErrorDetails);
    }
    
    public static void set(int newError) {
    	SLogger.d(TAG, "set error=" + newError);
    	error.set(newError);
    	errorDetails.set(Errors.get(newError));
    }
    
    public static int get() {
    	return error.get();
    }
    
    public static String getDetails() {
    	return errorDetails.get();
    }
}
