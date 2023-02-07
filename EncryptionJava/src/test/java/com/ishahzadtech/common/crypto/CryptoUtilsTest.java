package com.ishahzadtech.common.crypto;

import static org.junit.jupiter.api.Assertions.*;

import static com.ishahzadtech.common.crypto.CryptoUtils.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.util.Base64;
import java.util.Properties;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

//import com.ishahzadtech.common.BaseTest;

public class CryptoUtilsTest {

	private static Key cryptoKey;
	private static Properties props;
	private static Path keyStorePath;
	private static KeyStore pkcs12KeyStore;
	
	@BeforeAll
	static void preProcessing() throws Exception {
		props = loadProperties("encryption.properties");
		keyStorePath = getResourcePath("test-keystore.p12");
		
		final String keyAlias = props.getProperty("Key.Alias");
		final char[] keyPass = props.getProperty("Key.Password").toCharArray();
		final char[] keyStorePass = props.getProperty("KeyStore.Password").toCharArray();

		try (final InputStream fis = new FileInputStream(keyStorePath.toFile())) {
			pkcs12KeyStore = KeyStore.getInstance(KeyStoreType.getDefaultAsString());
			pkcs12KeyStore.load(fis, keyStorePass);
		}
		
		cryptoKey = pkcs12KeyStore.getKey(keyAlias, keyPass);
	}

	@Test
	void verifyKeyStoreExists() {
		final String keyStoreFilePath = keyStorePath.toFile().getAbsolutePath();
		final Boolean keyStoreExists = keyStoreExists(keyStoreFilePath);
		assertTrue(keyStoreExists);
	}

	@Test
	void verifyKeyStoreNotExists() {
		final String keyStoreFileName = keyStorePath.toFile().getName();
		final Boolean keyStoreExists = keyStoreExists(keyStoreFileName);
		assertFalse(keyStoreExists);
	}

	@Test
	void verifyLoadKeyStore() {
		final String keyStoreFilePath = keyStorePath.toFile().getAbsolutePath();
		final String keyStoreType = KeyStoreType.getDefaultAsString();
		final String keyStorePass = props.getProperty("KeyStore.Password", "");
		final String keyAlias = props.getProperty("Key.Alias");

		final KeyStore keyStore = loadKeyStore(keyStoreFilePath, keyStoreType, keyStorePass);

		assertAll("KeyStore Assertions", 
			() -> assertNotNull(keyStore),
			() -> assertEquals(keyStore.getType(), KeyStoreType.getDefaultAsString()),
			() -> assertTrue(keyStore.size() > 0), 
			() -> assertTrue(keyStore.containsAlias(keyAlias)));
	}

	@Test
	void verifyGetKeyFromKeyStore() {
		final String keyAlias = props.getProperty("Key.Alias");
		final String keyPass = props.getProperty("Key.Password");
		final String keyAlgorithm = props.getProperty("Key.Algorithm");
		final String keyFormat = props.getProperty("Key.Format");

		final Key cryptoKey = getKeyFromKeyStore(pkcs12KeyStore, keyAlias, keyPass);

		assertAll("Key Assertions", 
			() -> assertNotNull(cryptoKey),
			() -> assertEquals(cryptoKey.getAlgorithm(), keyAlgorithm),
			() -> assertEquals(cryptoKey.getFormat(), keyFormat));
	}

	@Test
	void verifyDoEncrypt() {
		final String algorithm = props.getProperty("Data.Crypto.Algorithm");
		final String encryptedData = props.getProperty("Data.Encrypted.Base64");
		final byte[] ivBytes = getPropertyBytes("Data.Crypto.IV");
		final byte[] plainTextData = props.getProperty("Data.PlainText").getBytes();
		
		final byte[] encryptedBytes = doEncrypt(algorithm, cryptoKey, plainTextData, ivBytes);
		final String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);
		
		assertEquals(encryptedBase64, encryptedData);
	}
	
	@Test
	void verifyDoDecrypt() {
		final String algorithm = props.getProperty("Data.Crypto.Algorithm");
		final String encryptedData = props.getProperty("Data.Encrypted.Base64");
		final byte[] ivBytes = getPropertyBytes("Data.Crypto.IV");
		final byte[] decodedData = Base64.getDecoder().decode(encryptedData);
		final byte[] plainData = props.getProperty("Data.PlainText").getBytes();
		
		final byte[] plainDataBytes = doDecrypt(algorithm, cryptoKey, decodedData, ivBytes);
		assertArrayEquals(plainDataBytes, plainData);
	}

	private static Path getResourcePath(final String resourceName) {
		return Paths.get("", "src", "test", "resources", resourceName);
	}
	
	private static Properties loadProperties(final String resourceName) throws IOException {
		final Properties properties = new Properties();
		final File propertiesFile = getResourcePath(resourceName).toFile();

		try (final InputStream is = new FileInputStream(propertiesFile)) {
			properties.load(is);
		}

		return properties;
	}
	
	private static byte[] getPropertyBytes(final String propertyName) {
		final String propertyValue = props.getProperty(propertyName);
		return Base64.getDecoder().decode(propertyValue);
	}
}
