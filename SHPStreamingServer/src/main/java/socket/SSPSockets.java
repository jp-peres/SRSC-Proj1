package socket;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.sql.PreparedStatement;
import java.net.SocketAddress;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SSPSockets extends DatagramSocket {

	private static String digits = "0123456789abcdef";
	private static final int ID_LENGTH = 6;
	private static final int MOVIE_ID_LEN = 30;
	private static final int NONCE_LEN = 4;
	private static final int PROXY_ID_LEN = 5;
	private static final int PBESUITE_LEN = 27;
	private static final int DIG_SIG_LEN = 17;
	private static final int PUBLIC_LEN = 2048;
	private static final int SHA256_LEN = 32;
	private static final int HELLO_LEN = 5;
	private static final String SIG_SUITE = "SHA512withRSA/PSS";
	private static final String SHA256 = "SHA-256";
	private MessageDigest nonceHash;
    private byte[] salt = new byte[] { (byte)0x7d, 0x60, 0x43, (byte)0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae };
    private int iterCount = 2048;
	// Properties
	private String cipherSuite;
	private String algorithm;
	private String mac1;
	private String mac2;
	private byte[] iv;
	private String sessionKeySize;
	private Key sessionKey;
	private String mac1KeySize;
	private Key mac1Key;
	private String mac2KeySize;
	private Key mac2Key;
	private IvParameterSpec ivSpec;
	private Cipher cipher;
	private Mac mac_1;
	private Mac mac_2;
	private boolean noMAC = true;

	public SSPSockets(SocketAddress sockAddr) throws SocketException, NoSuchAlgorithmException {
		super(sockAddr);
		nonceHash = MessageDigest.getInstance("SHA-256");
	}

	public SSPSockets(SocketAddress sockAddr, String config) throws IOException, NoSuchAlgorithmException {
		super(sockAddr);
		nonceHash = MessageDigest.getInstance("SHA-256");
		InputStream inputStream = null;
		try {
			inputStream = new FileInputStream(config);
		} catch (FileNotFoundException ex) {
			System.err.println("Configuration file not found!");
			System.exit(1);
		}
		Properties properties = new Properties();
		properties.load(inputStream);
		cipherSuite = properties.getProperty("CRYPTO-CIPHERSUITE");
		algorithm = cipherSuite.substring(0, cipherSuite.indexOf("/"));
		mac1 = properties.getProperty("MAC1-CIPHERSUITE");
		mac2 = properties.getProperty("MAC2-CIPHERSUITE");
		iv = toByteArray(properties.getProperty("IV").trim());
		sessionKeySize = properties.getProperty("SESSION-KEYSIZE");
		sessionKey = new SecretKeySpec(toByteArray(properties.getProperty("SESSION-KEY").trim()), algorithm);

		if (!mac1.equals("NULL")) {
			noMAC = false;
			mac1KeySize = properties.getProperty("MAC1-KEYSIZE");
			mac1Key = new SecretKeySpec(toByteArray(properties.getProperty("MAC1-KEY").trim()), mac1);
		}
		mac2KeySize = properties.getProperty("MAC2-KEYSIZE");
		mac2Key = new SecretKeySpec(toByteArray(properties.getProperty("MAC2-KEY").trim()), mac2);
		ivSpec = new IvParameterSpec(iv);

		try {
			cipher = Cipher.getInstance(cipherSuite);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static byte[] toByteArray(String string) {
		String[] stringArray = string.split(",");
		byte[] bytes = new byte[stringArray.length];
		for (int i = 0; i < stringArray.length; i++) {
			bytes[i] = new BigInteger(stringArray[i].substring(stringArray[i].indexOf("x") + 1), 16).byteValue();
		}
		return bytes;
	}

	public static String toHex(byte[] data, int length) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i != length; i++) {
			int v = data[i] & 0xff;
			buf.append(digits.charAt(v >> 4));
			buf.append(digits.charAt(v & 0xf));
		}
		return buf.toString();
	}

	public byte[] helloPayload(String[] args, byte[] buffer) throws Exception {
		String helloString = "Hello";
		String PWDCS = args[2];
		String pwd = args[1];
		String proxyID = args[0];
		if (proxyID.length() != 5)
			throw new Exception("ProxyID must be comprised of 5 characters.");
		String movie = args[3];
		movie = movie.substring(movie.indexOf("/") + 1);
		byte[] movieBytes = ByteBuffer.allocate(MOVIE_ID_LEN).put(movie.getBytes()).array();
		byte[] pwdcBytes = ByteBuffer.allocate(PBESUITE_LEN).put(PWDCS.getBytes()).array();

		Random r = new Random();
		byte[] nounce = ByteBuffer.allocate(4).putInt(r.nextInt()).array();

		System.arraycopy(helloString.getBytes(), 0, buffer, 0, HELLO_LEN);
		System.arraycopy(proxyID.getBytes(), 0, buffer, HELLO_LEN, PROXY_ID_LEN);
		System.arraycopy(movieBytes, 0, buffer, HELLO_LEN + PROXY_ID_LEN, MOVIE_ID_LEN);
		System.arraycopy(nounce, 0, buffer, HELLO_LEN + PROXY_ID_LEN + MOVIE_ID_LEN, NONCE_LEN);
		System.arraycopy(pwdcBytes, 0, buffer, HELLO_LEN + PROXY_ID_LEN + MOVIE_ID_LEN + NONCE_LEN,
				PBESUITE_LEN);

		MessageDigest pwdHash = MessageDigest.getInstance("SHA-256");
		pwdHash.update(pwd.getBytes());
		byte[] hashPass = pwdHash.digest();
		String hash = SSPSockets.toHex(hashPass, hashPass.length);
		
		byte[] hashInput = new byte[HELLO_LEN + PROXY_ID_LEN + MOVIE_ID_LEN + NONCE_LEN];
		System.arraycopy(buffer, 0, hashInput, 0, hashInput.length);
		MessageDigest dg = MessageDigest.getInstance("SHA-1");
		byte[] hashDig = dg.digest(hashInput);
		
		Cipher cipher = getPBECipher(PWDCS, hash, Cipher.ENCRYPT_MODE);
		
		byte[] finalCipher = cipher.doFinal(hashDig, 0, hashDig.length);
		System.out.println("finalCipher: " + finalCipher.length);
		System.out.println("Cipher sent: " + new String(finalCipher,StandardCharsets.UTF_8));
		System.arraycopy(finalCipher, 0, buffer,
				HELLO_LEN + PROXY_ID_LEN + MOVIE_ID_LEN + NONCE_LEN + PBESUITE_LEN, finalCipher.length);

		int payloadLen = HELLO_LEN + PROXY_ID_LEN + MOVIE_ID_LEN + NONCE_LEN + PBESUITE_LEN
				+ finalCipher.length;

		System.out.println("Payload expected: " + payloadLen);
		return preparePayload(buffer, payloadLen, (byte) 0x02, (byte) 0x01);
	}
	
	public byte[] getAuthChallenge(Map<String, String> accounts, SSPSockets s, SSPPacket ssp,
			byte[] data) throws Exception, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException,
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			SignatureException {

		byte[] helloString = new byte[5];
		System.arraycopy(data, 0, helloString, 0, 5);
		String hello = new String(helloString, StandardCharsets.UTF_8);
		if (!hello.equals("Hello")) {
			throw new Exception("Expected Hello");
		}

		byte[] proxyID = new byte[PROXY_ID_LEN];
		System.arraycopy(data, HELLO_LEN, proxyID, 0, PROXY_ID_LEN);
		String proxy = new String(proxyID);

		String hashPassword = accounts.get(proxy);

		if (hashPassword == null)
			throw new Exception("Proxy ID not found");

		byte[] movieNameBytes = new byte[MOVIE_ID_LEN];
		System.arraycopy(data, PROXY_ID_LEN + HELLO_LEN, movieNameBytes, 0, MOVIE_ID_LEN);
		String movieName = new String(movieNameBytes).trim();

		// Get nounce (reusing movieNameBytes buffer)
		byte[] nonce = new byte[NONCE_LEN];
		System.arraycopy(data, PROXY_ID_LEN + HELLO_LEN + MOVIE_ID_LEN, nonce, 0, NONCE_LEN);
		int val = ByteBuffer.wrap(nonce).getInt();

		byte[] pbeSuiteBytes = new byte[PBESUITE_LEN];
		System.arraycopy(data, PROXY_ID_LEN + HELLO_LEN + MOVIE_ID_LEN + NONCE_LEN, pbeSuiteBytes, 0, PBESUITE_LEN);
		String pbeSuite = new String(pbeSuiteBytes).trim();

		int pbeBytesSize = ssp.getPayloadSize() - (PROXY_ID_LEN + HELLO_LEN + MOVIE_ID_LEN + NONCE_LEN + PBESUITE_LEN);
		byte[] pbeBytes = new byte[pbeBytesSize];
		System.arraycopy(data, PROXY_ID_LEN + HELLO_LEN + MOVIE_ID_LEN + NONCE_LEN + PBESUITE_LEN, pbeBytes, 0,
				pbeBytesSize);

		System.out.println("Transmited cipher: " + new String(pbeBytes, StandardCharsets.UTF_8));
		System.out.println("Transmited cipher len: " + pbeBytes.length);

		Cipher cDec = s.getPBECipher(pbeSuite, hashPassword, Cipher.DECRYPT_MODE);

		byte[] c = cDec.doFinal(pbeBytes);
		MessageDigest dg = MessageDigest.getInstance("SHA-1");
		dg.update(data, 0, PROXY_ID_LEN + HELLO_LEN + MOVIE_ID_LEN + NONCE_LEN);

		if (!MessageDigest.isEqual(dg.digest(), c)) {
			throw new Exception("Tampered hello payload.");
		}

		// Prepare response to proxy
		byte[] sigInput = new byte[SHA256_LEN + NONCE_LEN + PUBLIC_LEN];
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(PUBLIC_LEN, new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();
		Signature signature = Signature.getInstance(SIG_SUITE);
		signature.initSign(keyPair.getPrivate());

		byte[] proxyNonceDigest = nonceHash.digest(nonce);
		SecureRandom r = new SecureRandom();
		byte[] serverNonce = ByteBuffer.allocate(4).putInt(r.nextInt()).array();
		byte[] publicKey = ByteBuffer.allocate(PUBLIC_LEN).put(keyPair.getPublic().getEncoded()).array();
		
		System.arraycopy(publicKey, 0, sigInput, 0, PUBLIC_LEN);
		System.arraycopy(proxyNonceDigest, 0, sigInput, PUBLIC_LEN, SHA256_LEN);
		System.arraycopy(serverNonce, 0, sigInput, PUBLIC_LEN + SHA256_LEN, NONCE_LEN);
		signature.update(sigInput);

		System.out.println("Data len: "+ data.length);
		byte[] signatureBytes = signature.sign();
		byte[] payload = new byte[SHA256_LEN + NONCE_LEN + PUBLIC_LEN + signatureBytes.length];
		System.arraycopy(SIG_SUITE.getBytes(), 0, data, 0, DIG_SIG_LEN);
		System.arraycopy(sigInput, 0, data, DIG_SIG_LEN, PUBLIC_LEN + NONCE_LEN + SHA256_LEN);
		System.arraycopy(signatureBytes, 0, data, DIG_SIG_LEN + PUBLIC_LEN + NONCE_LEN + SHA256_LEN,
				signatureBytes.length);

		int payloadLen = PUBLIC_LEN + NONCE_LEN + SHA256_LEN + signatureBytes.length;

		return preparePayload(data, payloadLen, (byte)0x02, (byte)0x02);
	}

	public Cipher getPBECipher(String PWDCS, String hash, int mode) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {
		PBEParameterSpec pSpec;
		PBEKeySpec pbeKeySpec;
		Key skey;
		SecretKeyFactory keyFact = SecretKeyFactory.getInstance(PWDCS);
		Cipher cipher = Cipher.getInstance(PWDCS);
		if (PWDCS.contains("AES")) {
			IvParameterSpec ivSp = new IvParameterSpec(new byte[16]);
			pSpec = new PBEParameterSpec(salt, iterCount, ivSp);
			pbeKeySpec = new PBEKeySpec(hash.toCharArray(), salt, iterCount);
			skey = keyFact.generateSecret(pbeKeySpec);
		} else {
			pbeKeySpec = new PBEKeySpec(hash.toCharArray());
			skey = keyFact.generateSecret(pbeKeySpec);
			pSpec = new PBEParameterSpec(salt, iterCount);
		}
		cipher.init(mode, skey, pSpec);
		return cipher;
	}

	/**
	 * Creates a new SSPPacket ciphering the frame and converting at SSPPacket into
	 * a byte array (was ciphering after thread sleep now ciphering before)
	 * 
	 * @param frame
	 * @param frameLen
	 * @return
	 */
	private byte[] preparePayload(byte[] frame, int frameLen, byte contentType, byte payloadType) {
		byte[] res = null;
		try {
			// string to byte[]
			// System.err.println("Incoming frame length: " + data.getLength());
			// String expected = new String(data.getData(),StandardCharsets.UTF_8);
			// System.err.println("Real frame:" + expected);
			SSPPacket packetToSend = createPacket(frame, frameLen, contentType, payloadType);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(packetToSend);
			oos.flush();
			res = baos.toByteArray();
			System.out.println("Prepare payload len:" + res.length);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return res;
	}

	@Override
	public void send(DatagramPacket data) throws IOException {
		super.send(data);
	}

	@Override
	public synchronized void receive(DatagramPacket data) throws IOException {
		super.receive(data);
	}

	private SSPPacket createPacket(byte[] payload, int payloadSize, byte contentType, byte payloadType)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			ShortBufferException, BadPaddingException, InvalidAlgorithmParameterException {
		if (contentType == 0x01)
			return createSSPPacket(payload, payloadSize);
		else {
			byte[] usefulBytes = new byte[payloadSize];
			System.arraycopy(payload, 0, usefulBytes, 0, payloadSize);
			return new SSPPacket(usefulBytes, contentType, payloadType, payloadSize);
		}
	}

	private SSPPacket createSSPPacket(byte[] payload, int payloadSize)
			throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException,
			BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
		int length = 0;

		if (!noMAC) {
			mac_1 = Mac.getInstance(mac1);
			mac_1.init(mac1Key);
			length = payloadSize + mac_1.getMacLength();
		} else
			length = payloadSize;

		byte[] messagePlusMac = new byte[length];
		// System.err.println("Original messagePlusMac: " + messagePlusMac.length);
		System.arraycopy(payload, 0, messagePlusMac, 0, payloadSize);

		if (!noMAC) {
			mac_1.update(payload, 0, payloadSize);
			mac_1.doFinal(messagePlusMac, payloadSize);
		}
		mac_2 = Mac.getInstance(mac2);
		mac_2.init(mac2Key);
		byte[] cipheredMessagePlusMac = new byte[cipher.getOutputSize(length) + mac_2.getMacLength()];
		int ctLen = cipher.doFinal(messagePlusMac, 0, length, cipheredMessagePlusMac, 0);
		// System.err.println("Cipher off - "+ctLen);
		mac_2.update(cipheredMessagePlusMac, 0, ctLen);
		mac_2.doFinal(cipheredMessagePlusMac, ctLen);
		return new SSPPacket(cipheredMessagePlusMac, cipheredMessagePlusMac.length);
	}

	public byte[] getFrame(SSPPacket p) throws NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, ShortBufferException, BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, ClassNotFoundException {
		byte[] ciphered = p.getPayload();
		int payloadSize = p.getPayloadSize();
		// System.out.println("PackageLength: " + payloadSize);
		// System.out.println("Cifered: " + ciphered.length);
		cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
		mac_2 = Mac.getInstance(mac2);
		mac_2.init(mac2Key);
		int cipherLen = payloadSize - mac_2.getMacLength();
		// System.out.println("CipherLen: " + cipherLen);
		byte[] macBytes = new byte[mac_2.getMacLength()];
		System.arraycopy(ciphered, cipherLen, macBytes, 0, macBytes.length);
		mac_2.update(ciphered, 0, cipherLen);

		// TODO: Add exception
		if (!MessageDigest.isEqual(mac_2.doFinal(), macBytes))
			System.err.println("Tampered 2");

		byte[] messagePlusMac = cipher.doFinal(ciphered, 0, cipherLen);
		// System.err.println("Message plus mac: " + messagePlusMac.length);

		if (noMAC) {
			return messagePlusMac;
		} else {
			mac_1 = Mac.getInstance(mac1);
			mac_1.init(mac1Key);
			int frameLen = messagePlusMac.length - mac_1.getMacLength();
			byte[] realFrame = new byte[frameLen];
			macBytes = new byte[mac_1.getMacLength()];

			// get macbytes
			System.arraycopy(messagePlusMac, frameLen, macBytes, 0, mac_1.getMacLength());

			// get frame
			System.arraycopy(messagePlusMac, 0, realFrame, 0, frameLen);
			mac_1.update(realFrame);
			// TODO: Add exception
			if (!MessageDigest.isEqual(mac_1.doFinal(), macBytes))
				System.err.println("Tampered 1");
			// System.err.println("Frame with id and nonce:" + frameLen);
			byte[] frameMsg = new byte[frameLen - (ID_LENGTH + NONCE_LEN)];
			// System.err.println("FrameMsg len: " + frameMsg.length);
			System.arraycopy(realFrame, ID_LENGTH + NONCE_LEN, frameMsg, 0, frameMsg.length);
			return frameMsg;
		}
	}
}
