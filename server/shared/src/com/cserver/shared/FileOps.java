package com.cserver.shared;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.List;

class FileTagObject {
	private static final int SIGN1 = 2423511;
	private static final int SIGN2 = 4667347;
	private static final String TAG = "FileTagObject";
	public String tag;
	public byte[] data;
	
	FileTagObject(String tag, byte[] data) {
		this.tag = tag;
		this.data = data;
	}
	
	byte [] getContent() {
		byte[] tagBytes = null;
		try {
			tagBytes = tag.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		if (tagBytes == null)
			return null;
		
		ByteBuffer bb = ByteBuffer.allocate(16 + tagBytes.length + data.length);
		bb.putInt(SIGN1);
		bb.putInt(tagBytes.length);
		bb.put(tagBytes);
		bb.putInt(SIGN2);
		bb.putInt(data.length);
		bb.put(data);
		
		return bb.array();
	}
}

public class FileOps {
	private static final String TAG = "FileOps";
	
	public static String readFileBinaryAsBase64(File file) {
		byte [] data = readFileBinary(file);
		if (data == null)
			return null;
		
		return Base64.encode(data);		
	}
	
	public static boolean writeFileBinaryAsBase64(File file, String content) {
		byte [] data = null;
		try {
			data = Base64.decode(content);
		} catch (Base64DecoderException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		if (data == null)
			return false;
		
		return writeFileBinary(file, data);
	}
	
	public static byte[] readFileBinary(File file) {
		FileInputStream is = null;
		ByteArrayOutputStream os = new ByteArrayOutputStream();		
		boolean bSuccess = false;
		
		try {
			is = new FileInputStream(file);			
			byte []tmpBuf = new byte[4096];
			
			int cbytes = 0;
			while (true) {
				cbytes = is.read(tmpBuf, 0, tmpBuf.length);
				if (cbytes == -1 || cbytes == 0) {
					break;
				}
				os.write(tmpBuf, 0, cbytes);
			}
			bSuccess = true;
		} catch (IOException e) {
			SLogger.exception(TAG, e);
		} finally {
		  	try {
		  		if (is != null)
		  			is.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
		    	SLogger.exception(TAG, e);
			}
	  	}
	  	
		if (bSuccess)
			return os.toByteArray();
		else
			return null;
	}

	public static boolean writeFileBinaryTagged(File file, String tag, byte[] data) {
		FileTagObject object = new FileTagObject(tag, data);
		return writeFileBinaryInternal(file, object.getContent(), true);
	}
	
	public static boolean writeFileBinaryInternal(File file, byte[] data, boolean append) {
		boolean bSuccess = false;
		
        FileOutputStream out = null;   
        //SLogger.d(TAG, "writeFile=" + content);
        try {
        	out = new FileOutputStream(file, append);
       		out.write(data, 0, data.length);
       		bSuccess = true;
        } catch (IOException e) {
	    	SLogger.exception(TAG, e);
        } finally {
        	if (out != null)
				try {
					out.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					SLogger.exception(TAG, e);
				}
        }
        
		return bSuccess;
	}
	
	public static boolean writeFileBinary(File file, byte[] data) {
		return writeFileBinaryInternal(file, data, false);
	}
	
	public static String readFile(File file) {
		
		byte[] content = readFileBinary(file);
		if (content == null)
			return null;

		String result = null;
		try {
			result = new String(content, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		return result;
	}
	
	public static boolean writeFile(File file, String content) {
		boolean bSuccess = false;
		try {
			bSuccess = writeFileBinary(file, content.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
		}
		
		return bSuccess;
	}
	
	public static boolean writeFileLines(File file, List<String> lines) {
		BufferedWriter writer = null;
		boolean bSuccess = false;
		try {
			writer = new BufferedWriter( new FileWriter( file));
			for (String line : lines) {
				writer.write(line + '\n');
			}
			bSuccess = true;
		} catch ( IOException e) {
			SLogger.exception(TAG, e);
		} finally {
			try {
				if ( writer != null)
					writer.close( );
			} catch ( IOException e) {
				SLogger.exception(TAG, e);
			}
	    }
		return bSuccess;
	}
	
	public static void deleteFileRecursive(File fileOrDirectory) {
		SLogger.i(TAG, "deleteFileRecursive file=" + fileOrDirectory.getAbsolutePath());
	    if (fileOrDirectory.isDirectory())
	        for (File child : fileOrDirectory.listFiles())
	        	deleteFileRecursive(child);

	    fileOrDirectory.delete();
	}
	
	public static boolean copyFile(String srcPath, String dstPath) {
		InputStream is = null;
		FileOutputStream os = null;
		boolean result = false;
		try {
		    is = new FileInputStream(srcPath);
		    SLogger.d(TAG, "is=" + is);
		    os = new FileOutputStream(dstPath);
		    SLogger.d(TAG, "os=" + is);
		    byte []buffer = new byte[1024];
		    int cbytes;
		    while (true) {
		    	cbytes = is.read(buffer);
		    	if (cbytes > 0)
		    		os.write(buffer, 0, cbytes);
		    	else
		    		break;
		    }
		    result = true;
		} catch (IOException e) {
		    //log the exception
			SLogger.e(TAG, "IOException" + e.toString());
			SLogger.exception(TAG, e);
		} catch (Exception e) {
			SLogger.e(TAG, "Exception" + e.toString());
		} finally {
			if (is != null)
				try {
					is.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					SLogger.exception(TAG, e);
				}
			
			if (os != null)
				try {
					os.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					SLogger.exception(TAG, e);
				}
		}
		SLogger.d(TAG, "result=" + result);
		return result;	
	}
}
