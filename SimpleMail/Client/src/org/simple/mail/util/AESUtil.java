package org.simple.mail.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class AESUtil {
	protected static final String ALGORITHM = "AES";
	protected static final String SALT = "99552371f24b195043148eb3e59d9fe84eb7efea";
	protected static final int KEY_LENGTH = 256;
	protected static final int IV_LENGTH = 16;

	public static void main(String[] args) {
		
//		String abc = "aabc\nasdf\nsdfasdf\n";
//		System.out.println(abc);
		
		BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
		String line = "";
		try {
			line += user.readLine() + "\n";
			line += user.readLine() + "\n";
			line += user.readLine() + "\n";
			line += user.readLine() + "\n";
			
			System.out.println(line);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
//		String password = "123456";
//		String msg = "hello\n.";
//		AESUtil aesCryptor1 = new AESUtil();
//		AESUtil aesCryptor2 = new AESUtil();
//		try {
//			SecretKey key1 = aesCryptor1.getSecretKey(password);
//			SecretKey key2 = aesCryptor2.getSecretKey(password);
//			
//			
//			String s1 = aesCryptor1.encryptString(key1, msg);
//			s1 = s1.trim();
//			System.out.println(s1);
//			
//			System.out.println(aesCryptor2.decryptString(key2, s1));
//			
//		
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}		
		
//		String test = "   abc  ";
//		System.out.println(test.trim());
//		System.out.println(test);
	}

	public AESUtil() {
		Security.addProvider(new BouncyCastleProvider());
	}

	public SecretKey getSecretKey(String secretKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), SALT.getBytes(), 65536, KEY_LENGTH);
		SecretKey tmp = factory.generateSecret(spec);

		return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);

	}

	public byte[] encryptBytes(Key key, byte[] plainBytes) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecureRandom random = new SecureRandom();
		byte[] iv = random.generateSeed(IV_LENGTH);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		byte[] cipherBytes = cipher.doFinal(plainBytes);

		int cipherLength = cipherBytes.length;

		byte[] out = new byte[IV_LENGTH + cipherLength];
		System.arraycopy(iv, 0, out, 0, IV_LENGTH);
		System.arraycopy(cipherBytes, 0, out, IV_LENGTH, cipherLength);

		return out;
	}

	public String encryptString(Key key, String plainText)
			throws UnsupportedEncodingException, GeneralSecurityException {
		String cipherText;
		cipherText = Base64.toBase64String(encryptBytes(key, plainText.getBytes("UTF-8")));
		return cipherText;
	}

	public byte[] decryptBytes(Key key, byte[] cipherBytes) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		byte[] iv = new byte[IV_LENGTH];
		System.arraycopy(cipherBytes, 0, iv, 0, IV_LENGTH);
		int cipherLength = cipherBytes.length - IV_LENGTH;
		byte[] cipherData = new byte[cipherLength];
		System.arraycopy(cipherBytes, IV_LENGTH, cipherData, 0, cipherLength);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		return cipher.doFinal(cipherData);
	}

	public String decryptString(SecretKey key, String cipherText)
			throws UnsupportedEncodingException, GeneralSecurityException {
		byte[] cipherBytes = Base64.decode(cipherText);
		return new String(decryptBytes(key, cipherBytes), "UTF-8");
	}

}
