package com.bct.mmrcl.util;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
public class EncryptionUtil {

	@Autowired
	private Environment env;

	private static final String ALGORITHM_PROPERTY = "encryption.algorithm";
	private static final String SECRET_KEY_PROPERTY = "encryption.secretkey";

	private String getAlgorithm() {
		return env.getProperty(ALGORITHM_PROPERTY); 
	}

	private String getSecretKey() {
		return env.getProperty(SECRET_KEY_PROPERTY);
	}

	private SecretKeySpec getSecretKeySpec(String secret) {
		return new SecretKeySpec(secret.getBytes(), getAlgorithm());
	}

	public String encrypt(String data) throws Exception {
		String secret = getSecretKey();
		String secretkey = getLast16Digits(secret);
		String algorithm = getAlgorithm();
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(secretkey));
		byte[] encryptedBytes = cipher.doFinal(data.getBytes());
		return Base64.getEncoder().encodeToString(encryptedBytes);
	}

	public String decrypt(String encryptedData) throws Exception {
		String secret = getSecretKey();
		String secretkey = getLast16Digits(secret);
		String algorithm = getAlgorithm();
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(secretkey));
		byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
		byte[] decryptedBytes = cipher.doFinal(decodedBytes);
		return new String(decryptedBytes);
	}
	public static String getLast16Digits(String str) {
		if (str.length() <= 16) {
			return str;
		}
		return str.substring(str.length() - 16);
	}
}
