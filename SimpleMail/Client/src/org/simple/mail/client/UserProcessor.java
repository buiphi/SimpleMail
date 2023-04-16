package org.simple.mail.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

import org.simple.mail.util.Command;
import org.simple.mail.util.Mail;
import org.simple.mail.util.Request;
import org.simple.mail.util.Response;
import org.simple.mail.util.TcpChannel;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.simple.mail.util.AESUtil;
import org.simple.mail.util.RSAUtil;
import org.simple.mail.util.SignatureUtil;

public class UserProcessor {
	private static final String SIG_HEADER = "SIG:";
	private static final String BODY = "BODY:";
	private static final String KEY = "KEY:";

	private Socket socket;
	private Request request;
	private Response response;
	private TcpChannel channel;

	public UserProcessor(Socket sock) {
		this.socket = sock;
		try {
			channel = new TcpChannel(socket);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public int process() throws IOException, GeneralSecurityException, DataLengthException, OperatorCreationException,
			PKCSException, CryptoException {
		String command = request.getCommand();
		channel.sendRequest(request);
		response = channel.receiveResponse();
		if (response != null) {
			handleResponse(command);
			return 0;
		} else
			return -1;
	}

	public void setResponse(Response res) {
		this.response = res;
	}

	public void setRequest(Request req) {
		this.request = req;
	}

	private void handleResponse(String command) throws IOException, GeneralSecurityException, DataLengthException,
			OperatorCreationException, PKCSException, CryptoException {
		System.out.println("Receive: " + response.craftToString());

		String returnCode = response.getCode();
		if (returnCode.compareTo(Response.SUCCESS) == 0) {
			if (command.compareToIgnoreCase(Command.DATA) == 0)
				doDataResponse();
			else if (command.compareToIgnoreCase(Command.LIST) == 0)
				doListResponse();
			else if (command.compareToIgnoreCase(Command.RETRIEVE) == 0)
				doRetrieveResponse();
		}
	}

	private void doDataResponse() throws GeneralSecurityException, OperatorCreationException, PKCSException,
			DataLengthException, CryptoException, IOException {

		System.out.println("Send: ");

		BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
		String inputLine;
		StringBuilder messageBuilder = new StringBuilder();
		
		boolean isEndOfMail = false;
		while (!isEndOfMail) {
			inputLine = userInput.readLine();
			if (inputLine.compareTo(Mail.END_MAIL) != 0)
				messageBuilder.append(inputLine).append("\n");
			else
				isEndOfMail = true;
		}

		StringBuilder builder = encryptMail(userInput, messageBuilder.toString().trim());
		if (builder == null)
			return;

		System.out.println("Sending mail...");
		channel.sendRequest(new Request(builder.toString()));
		channel.sendRequest(new Request(Mail.END_MAIL));
		response = channel.receiveResponse();
		System.out.println("Receive from server: " + response.craftToString());
	}

	private StringBuilder encryptMail(BufferedReader userInput, String message) {
		StringBuilder builder = null;
		try {
			AESUtil aesCryptor = new AESUtil();
			
			String aesKey = new String(new SecureRandom().generateSeed(32));
			SecretKey key = aesCryptor.getSecretKey(aesKey);
			// encrypt AES message
			String encryptedMessage = aesCryptor.encryptString(key, message);

			// encrypt AES Key by RSA
			RSAUtil rsaCryptor = new RSAUtil();
			RSAKeyParameters recipientPublicKey;
			String recipientPublicKeyFile = null, senderPrivateKeyFile = null, rsaPassword;

			boolean isFileExist = false;
			while (!isFileExist) {
				System.out.print("Path to recipient's public key:");
				recipientPublicKeyFile = userInput.readLine();

				if (Paths.get(recipientPublicKeyFile).toFile().exists())
					isFileExist = true;
				else
					System.err.println("File not found.");
			}

			recipientPublicKey = rsaCryptor.getPublicKey(recipientPublicKeyFile);
			String encryptedAesKey = rsaCryptor.encryptString(recipientPublicKey, aesKey);

			// create signature (
			isFileExist = false;
			while (!isFileExist) {
				System.out.print("Path to your private key:");
				senderPrivateKeyFile = userInput.readLine();
				if (Paths.get(senderPrivateKeyFile).toFile().exists())
					isFileExist = true;
				else
					System.err.println("File not found.");
			}

			System.out.print("Password for using private key:");
			rsaPassword = userInput.readLine();

			String signature = createSignature(encryptedMessage, senderPrivateKeyFile, rsaPassword);
						
			if (!signature.isEmpty()) {
				builder = new StringBuilder();
				builder.append(SIG_HEADER + signature);
				builder.append("\n");
				builder.append(KEY + encryptedAesKey);
				builder.append("\n");
				builder.append(BODY + encryptedMessage);
			}
		} catch (Exception e) {
			System.err.println("Error: There are some error while encrypt message");
			//e.printStackTrace();
		}
		return builder;
	}

	private String createSignature(String encryptedMessage, String senderPrivateKeyFile, String rsaPassword)
			throws IOException, OperatorCreationException, CryptoException, UnsupportedEncodingException {
		SignatureUtil signOperator = new SignatureUtil();
		String signature = new String();
		RSAKeyParameters senderPrivateKey;
		try {
			senderPrivateKey = signOperator.getPrivateKey(senderPrivateKeyFile, rsaPassword);
			signature = signOperator.signString(senderPrivateKey, encryptedMessage);
		} catch (PKCSException e) {
			System.err.println("Error: Cannot get private key. Maybe wrong password.");
			//System.err.println(e.getMessage());
		}
		return signature;
	}

	private void doListResponse() throws IOException {
		StringBuilder builder = new StringBuilder();
		int numberOfMail = Integer.parseInt(response.getNotice());
		for (int i = 0; i < numberOfMail; i++)
			builder.append(channel.receiveLine());
		System.out.println(builder.toString());
	}

	private void doRetrieveResponse() throws IOException, InvalidCipherTextException, OperatorCreationException,
			PKCSException, GeneralSecurityException {
		StringBuilder builder = new StringBuilder();
		String line;
		int leftBytes = Integer.parseInt(response.getNotice()) + 1;

		String signature = null, encryptedMessage = null, encryptedAesKey = null;
		while (leftBytes > 0) {
			line = channel.receiveLine();
			leftBytes = leftBytes - line.length();

			if (line.startsWith(SIG_HEADER) == true)
				signature = line.substring(SIG_HEADER.length());
			else if (line.startsWith(BODY) == true)
				encryptedMessage = line.substring(BODY.length()).trim();
			else if (line.startsWith(KEY) == true)
				encryptedAesKey = line.substring(KEY.length());
			else
				builder.append(line); //append date,from,to
		}
		decryptMail(builder, signature, encryptedMessage, encryptedAesKey);
	}

	private void decryptMail(StringBuilder builder, String signature, String encryptedMessage,
			String encryptedAesKey)
			throws IOException, UnsupportedEncodingException, OperatorCreationException, PKCSException,
			InvalidCipherTextException, NoSuchAlgorithmException, InvalidKeySpecException, GeneralSecurityException {
		SignatureUtil verifyOperator = new SignatureUtil();
		// Enter password for generating secret key
		RSAKeyParameters senderPublicKey;
		String senderPublicKeyFile;

		BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("Path to sender's public key:");
		senderPublicKeyFile = user.readLine();
		senderPublicKey = verifyOperator.getPublicKey(senderPublicKeyFile);

		if (verifyOperator.verifyString(senderPublicKey, encryptedMessage, signature)) {
			// Import server's private key
			RSAUtil rsaCryptor = new RSAUtil();
			RSAKeyParameters senderPrivateKey;
			String senderPrivateKeyFile, rsaPassword;

			System.out.print("Path to your private key:");
			senderPrivateKeyFile = user.readLine();

			System.out.print("Password for using private key:");
			rsaPassword = user.readLine();

			senderPrivateKey = verifyOperator.getPrivateKey(senderPrivateKeyFile, rsaPassword);

			String decryptedAesKey = rsaCryptor.decryptString(senderPrivateKey, encryptedAesKey);

			AESUtil aesCryptor = new AESUtil();
			SecretKey secretKey = aesCryptor.getSecretKey(decryptedAesKey);

			builder.append(aesCryptor.decryptString(secretKey, encryptedMessage));
			System.out.println(builder.toString());

		} else
			System.out.println("Message is not authentic");
	}

}
