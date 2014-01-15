package com.cserver.shared;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface IKeyResolver {
	PublicKey getPublicKey(long ownerId, long keyId);
	PrivateKey getPrivateKey(long ownerId, long keyId);
}
