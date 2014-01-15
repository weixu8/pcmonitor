package com.cserver.shared;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;

public class Message implements IBytesDumpable {
	
	public long id = -1;
	public int direction = -1;
	public int msgType = -1;
	public int state = -1;
	public int bytesType = -1;
	public long from = -1;
	public long peer = -1;
	public long date = -1;
	public byte[] bytes = null;
	
	public int status = -1;
	public long inviteId = -1;
	
	public long signKeyId = -1;
	public long encKeyId = -1;
	
	public String mimeType = null;
	public String displayName = null;
	public String filePath = null;
	
	public static final long SIGN = 31415926535897L;
	
	public static final int DIRECTION_IN = 1;
	public static final int DIRECTION_OUT = 2;
	
	public static final int STATE_UNREAD = 1;
	public static final int STATE_READ = 2;
	
	public static final int MSG_TYPE_GENERAL = 1;
	public static final int MSG_TYPE_INVITATION_REQUEST = 2;
	public static final int MSG_TYPE_INVITATION_REPLY = 3;
	public static final int MSG_TYPE_USER_PROFILE_REPLY = 4;
	public static final int MSG_TYPE_USER_PROFILE_REQUEST = 5;
	
	public static final int CONTENT_TYPE_TEXT = 1;
	public static final int CONTENT_TYPE_PNG = 2;
	public static final int CONTENT_TYPE_FILE = 3;
	
	public static final int INVITATION_ACCEPTED = 1;
	public static final int INVITATION_REJECTED = 2;
	
	private static final String TAG = "Message";
	
	public Message() {
		
	}
	
	private int getHeaderLength() {
		return (8*8 + 8*4);
	}
	
	public byte[] toBytes() {
		
		byte [] mimeTypeBytes = null;
		byte [] displayNameBytes = null;
		
    	try {
    		if (mimeType != null)
    			mimeTypeBytes = mimeType.getBytes("UTF-8");
    		if (displayName != null)
    			displayNameBytes = displayName.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
			return null;
		}		
    	
    	int mimeTypeLength = (mimeTypeBytes != null) ? mimeTypeBytes.length : 0;
    	int displayNameLength  = (displayNameBytes != null) ? displayNameBytes.length : 0;
    	int bytesLength = (bytes != null) ? bytes.length : 0;
        
        ByteBuffer bb = ByteBuffer.allocate(mimeTypeLength + displayNameLength + bytesLength + getHeaderLength());
        bb.putLong(SIGN);
        bb.putLong(id);
        bb.putLong(peer);
        bb.putLong(from);
        bb.putLong(date);
        bb.putLong(signKeyId);
        bb.putLong(encKeyId);
        bb.putLong(inviteId);
        
        bb.putInt(direction);
        bb.putInt(state);
        bb.putInt(msgType);
        bb.putInt(status);
        bb.putInt(bytesType);
        bb.putInt(mimeTypeLength);
        bb.putInt(displayNameLength);
        bb.putInt(bytesLength);
        
        if (mimeTypeBytes != null)
        	bb.put(mimeTypeBytes);
        
        if (displayNameBytes != null)
        	bb.put(displayNameBytes);
        
        if (bytes != null)
        	bb.put(bytes);
    
        return bb.array();
	}
	
	public boolean parseBytes(byte[] data) {
		if (data.length < getHeaderLength()) {
			SLogger.e(TAG, "invalid data size data.length=" + data.length);
			return false;
		}
		
		ByteBuffer bb = ByteBuffer.wrap(data);
		
		long msgSign = bb.getLong();
		long id = bb.getLong();
		long peer = bb.getLong();
		long from = bb.getLong();
		long date = bb.getLong();
		long signKeyId = bb.getLong();
		long encKeyId = bb.getLong();
		long inviteId = bb.getLong();
		
		int direction = bb.getInt();
		int state = bb.getInt();
		int msgType = bb.getInt();
		int status = bb.getInt();
		int bytesType = bb.getInt();
		int mimeTypeLength = bb.getInt();
		int displayNameLength = bb.getInt();
		int bytesLength = bb.getInt();
		
		if (msgSign != SIGN) {
			SLogger.e(TAG, "invalid msg sign");
			return false;
		}
			
		if ((bytesLength < 0) || (mimeTypeLength < 0) || (displayNameLength < 0)) {
			SLogger.e(TAG, "invalid bytesLength=" + bytesLength + " mimeTypeLength=" + mimeTypeLength
					+ " displayNameLength=" + displayNameLength);
			return false;
		}
		
		if ((bytesLength + mimeTypeLength + displayNameLength + getHeaderLength()) != data.length) {
			SLogger.e(TAG, "invalid msg bytes length=" + bytesLength + " data.length=" + data.length);
			return false;
		}
		
		try {
			byte [] mimeTypeBytes = null;
			if (mimeTypeLength != 0) {
				mimeTypeBytes = new byte[mimeTypeLength];
				bb.get(mimeTypeBytes);
				mimeType = new String(mimeTypeBytes, "UTF-8");
			}
			
			byte [] displayNameBytes = null;
			if (displayNameLength != 0) {
				displayNameBytes = new byte[displayNameLength];
				bb.get(displayNameBytes);
				displayName = new String(displayNameBytes, "UTF-8");
			}
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			SLogger.exception(TAG, e);
			return false;
		} 
		
		byte bytes[] = null;
		if (bytesLength != 0) {
			bytes = new byte[bytesLength];
			bb.get(bytes);
		}
		
		this.id = id;
		this.direction = direction;
		this.bytesType = bytesType;
		this.peer = peer;
		this.from = from;
		this.signKeyId = signKeyId;
		this.encKeyId = encKeyId;
		this.bytes = bytes;
		this.date = date;
		this.state = state;
		this.msgType = msgType;
		this.status = status;
		this.inviteId = inviteId;
		
		return true;
	}

}
