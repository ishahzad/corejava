package com.ishahzadtech.common.crypto;

/**
 * Class representing supported key store types in a type safe manner.
 * 
 * @author ishahzad (Irfan Shahzad) - ishahzadtech.com
 * @since 1.0
 */
public enum KeyStoreType {

	JKS, JCEKS, PKCS12;
	
	public static KeyStoreType getDefault() {
		return PKCS12;
	}
	
	public static String getDefaultAsString() {
		return getDefault().name();
	}
}
