package com.ishahzadtech.common.crypto;

import java.io.FileInputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import com.ishahzadtech.common.OperationFailureException;

/**
 * This class contains method for handling cryptographic functionalities. 
 * 
 * @author ishahzad (Irfan Shahzad) - ishahzadtech.com
 * @since 1.0
 */
public class CryptoUtils {
	
	/**
	 * Method to verify whether provided KeyStore exists in the file system.
	 * 
	 * @param keyStorePath fully qualified path for the KeyStore.
	 * @return true if provided keyStore exists on provided keyStorePath, <code>false</code> otherwise. 
	 */
	public static Boolean keyStoreExists(final String keyStorePath) {
		if (keyStorePath == null)
			throw new IllegalArgumentException("keyStorePath is a required parameter");
		
		final Path filePath = FileSystems.getDefault().getPath(keyStorePath);
		return Files.isRegularFile(filePath);
	}
	
	/**
	 * Method for initializing <code>KeyStore</code> object based on provided keyStorePath. 
	 * 
	 * @param keyStorePath fully qualified path for the KeyStore.
	 * @param keyStoreType type of the KeyStore to be used for initialization purposes.
	 * @param keyStorePass optional key store password for security.
	 * @return KeyStore initialized KeyStore object based on provided parameters.
	 * 
	 * @throws IllegalArgumentException in case provided KeyStore doesn't exists in the file system. 
	 * @throws OperationFailureException in case KeyStore object can't created using provided parameters.
	 * 
	 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">KeyStoreType</a>
	 * @see KeyStore 
	 * @see KeyStoreType
	 */
	public static KeyStore loadKeyStore(final String keyStorePath, KeyStoreType keyStoreType, final char[] keyStorePass) {
		if (!keyStoreExists(keyStorePath))
			throw new IllegalArgumentException("KeyStorePath does not exist: " + keyStorePath);
		
		if (keyStoreType == null)
			keyStoreType = KeyStoreType.getDefault();
		
		try (final FileInputStream fis = new FileInputStream(keyStorePath)) {
			final KeyStore keystore = KeyStore.getInstance(keyStoreType.name());
			keystore.load(fis, keyStorePass);
			return keystore;
			
		} catch (Exception ex) {
			throw new OperationFailureException("Unable to load keystore: " + keyStorePath, ex);
		}
	}
	
	/**
	 * Method for initializing <code>KeyStore</code> object based on provided keyStore parameters. 
	 * Method with char[] should be preferred for security reasons.
	 * 
	 * @param keyStorePath fully qualified path for the KeyStore.
	 * @param keyStoreType type of the KeyStore to be used for initialization purposes.
	 * @param keyStorePass optional key store password for security.
	 * @return KeyStore initialized KeyStore object based on provided parameters.
	 * 
	 * @throws IllegalArgumentException in case provided KeyStore doesn't exists in the file system. 
	 * @throws OperationFailureException in case KeyStore object can't created using provided parameters.
	 * 
	 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">KeyStoreType</a>
	 * @see KeyStore 
	 */
	public static KeyStore loadKeyStore(final String keyStorePath, final String keyStoreType, final String keyStorePass) {
		final char[] password = keyStorePass == null ? null : keyStorePass.toCharArray();
		final KeyStoreType type = KeyStoreType.valueOf(keyStoreType);
		
		return loadKeyStore(keyStorePath, type , password);
	}
	
	/**
	 * Method for retrieving key from provided {@link KeyStore} object.
	 * 
	 * @param keyStore KeyStore object from which key needs to be retrieved.
	 * @param keyAlias alias against which key needs to be obtained.
	 * @param keyPass key password for security purposes.
	 * @return {@link Key} object retried from given <code>keyStore</code>.
	 * 
	 * @throws IllegalArgumentException in case provided <code>keyStore</code> is null or it doesn't contain <code>keyAlias</code>.
	 * @throws OperationFailureException in case KeyStore object can't created using provided parameters.
	 */
	public static Key getKeyFromKeyStore(final KeyStore keyStore, final String keyAlias, final char[] keyPass) {
		try {
			if (keyStore == null || keyAlias == null || !keyStore.containsAlias(keyAlias))
				throw new IllegalArgumentException("provided keystore or keyAlias in invalid");
			
			final Key key = keyStore.getKey(keyAlias, keyPass);
			return key;
			
		} catch (Exception ex) {
			throw new OperationFailureException("Unable to load key: " + keyAlias, ex);
		}
	}
	
	/**
	 * Method for retrieving key from provided {@link KeyStore} object.
	 * Method with char[] should be preferred for security reasons.
	 * 
	 * @param keyStore KeyStore object from which key needs to be retrieved.
	 * @param keyAlias alias against which key needs to be obtained.
	 * @param keyPass key password for security purposes.
	 * @return {@link Key} object retried from given <code>keyStore</code>.
	 * 
	 * @throws IllegalArgumentException in case provided <code>keyStore</code> is null or it doesn't contain <code>keyAlias</code>.
	 * @throws OperationFailureException in case KeyStore object can't created using provided parameters.
	 */
	public static Key getKeyFromKeyStore(final KeyStore keyStore, final String keyAlias, final String keyPass) {
		final char[] password = keyPass == null ? null : keyPass.toCharArray();
		return getKeyFromKeyStore(keyStore, keyAlias, password);
	}
	
	/**
	 * Helper method for retrieving key by internally loading the KeyStore. 
	 * This method is preferred when <code>KeyStore</code> object is not really needed.
	 * 
	 * @param keyStorePath fully qualified path for the KeyStore.
	 * @param keyStoreType type of the KeyStore to be used for initialization purposes.
	 * @param keyStorePass key store password for security.
	 * @param keyAlias alias against which key needs to be obtained.
	 * @param keyPass key password for security purposes.
	 * @return {@link Key} object retried from the <code>KeyStore</code>.
	 * 
	 * @throws OperationFailureException in case KeyStore object can't created using provided parameters.
	 */
	public static byte[] getKeyFromKeyStore(final String keyStorePath, final String keyStoreType, final String keyStorePass, 
											final String keyAlias, final String keyPass) {
		
		final KeyStore keyStore = loadKeyStore(keyStorePath, keyStoreType, keyStorePass);
		final Key cryptoKey = getKeyFromKeyStore(keyStore, keyAlias, keyStorePass);
		return cryptoKey.getEncoded();
	}
	
	public static byte[] doEncrypt(final String algorithm, final Key key, final byte[] data, final byte[] iv) {
		if (algorithm == null)
			throw new IllegalArgumentException("encryption algorithm is required");
		
		try {
			final Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			return cipher.doFinal(data);
			
		} catch (Exception ex) {
			throw new OperationFailureException("Data encryption failed with cipher: " + algorithm, ex);
		}
	}
	
	public static byte[] doDecrypt(final String algorithm, final Key key, final byte[] data, final byte[] iv) {
		if (algorithm == null)
			throw new IllegalArgumentException("decryption algorithm is required");
		
		try {
			final Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			return cipher.doFinal(data);
			
		} catch (Exception ex) {
			throw new OperationFailureException("Data decryption failed with cipher: " + algorithm, ex);
		}
	}
}
