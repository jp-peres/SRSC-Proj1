package socket;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.net.SocketAddress;
import java.util.Map;
import java.util.Properties;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SSPSockets extends DatagramSocket {
	
	// DH params
	private static BigInteger g = new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
          + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
          + "410b7a0f12ca1cb9a428cc", 16);
    private static BigInteger p = new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
          + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
          + "f0573bf047a3aca98cdf3b", 16);
    
    
	private static String digits = "0123456789abcdef";
	private static final int ID_LENGTH = 6;
	private static final int MOVIE_ID_LEN = 30;
	private static final int NONCE_LEN = 4;
	private static final int PROXY_ID_LEN = 5;
	private static final int PBESUITE_LEN = 27;
	private static final int DIG_SIG_LEN = 17;
	private static final int PUBLIC_CIPH_LEN = 256;
	private static final int PUBLIC_LEN = 2048;
	private static final int SHA256_LEN = 32;
	private static final int HELLO_LEN = 5;
	private static final int FINISH_LEN = 8;
	
	private byte[] secretKeyHS;
	private static final int CIPHER_LEN = 64;
	private static final String SHA256 = "SHA-256";
	private String mySigSuite;
	private MessageDigest nonceHash;
    private byte[] salt = new byte[] { (byte)0x7d, 0x60, 0x43, (byte)0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae };
    private int iterCount = 2048;
    
    private byte[] n1;
    private byte[] n2;
    private byte[] n3;
    private byte[] n4;
    
    private KeyPair myDHKeyPair;
    private Key otherPubDHKey;
    private KeyAgreement myKeyAgree;
    private byte[] secretBytes;
    
    private KeyPair myKeys;
    private Key pubKeyProxy;
    private Key pubKeyServer;
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
	private SecureRandom r;
	private String movieName;
	
	
	public SSPSockets(SocketAddress sockAddr) throws SocketException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
		super(sockAddr);
		nonceHash = MessageDigest.getInstance(SHA256);
		DHParameterSpec dhParams = new DHParameterSpec(p, g);
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
	    keyGen.initialize(dhParams);
		r = new SecureRandom();
		myKeyAgree = KeyAgreement.getInstance("DH");
		myDHKeyPair = keyGen.generateKeyPair();
        myKeyAgree.init(myDHKeyPair.getPrivate());
        
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

	public String getMovieName() {
		return movieName;
	}
	
	public byte[] helloPayload(String[] args, byte[] buffer) throws Exception {
		String helloString = "Hello";
		String PWDCS = args[2];
		String pwd = args[1];
		String proxyID = args[0];
		if (proxyID.length() != 5)
			throw new Exception("ProxyID must be comprised of 5 characters.");
		String movie = args[3];
		byte[] movieBytes = ByteBuffer.allocate(MOVIE_ID_LEN).put(movie.getBytes()).array();
		byte[] pwdcBytes = ByteBuffer.allocate(PBESUITE_LEN).put(PWDCS.getBytes()).array();

		byte[] nounce = ByteBuffer.allocate(4).putInt(r.nextInt()).array();
		n1 = nounce;

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
		System.arraycopy(finalCipher, 0, buffer,
				HELLO_LEN + PROXY_ID_LEN + MOVIE_ID_LEN + NONCE_LEN + PBESUITE_LEN, finalCipher.length);

		int payloadLen = HELLO_LEN + PROXY_ID_LEN + MOVIE_ID_LEN + NONCE_LEN + PBESUITE_LEN
				+ finalCipher.length;
		
		return preparePayload(buffer, payloadLen, (byte) 0x02, (byte) 0x01);
	}
	
	public byte[] getAuthChallenge(Map<String, String> accounts, SSPPacket ssp,
			byte[] data, String SIG_SUITE) throws Exception, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException,
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
		movieName = new String(movieNameBytes).trim();

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

		Cipher cDec = getPBECipher(pbeSuite, hashPassword, Cipher.DECRYPT_MODE);

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
		myKeys = keyGen.generateKeyPair();
		Signature signature = Signature.getInstance(SIG_SUITE);
		signature.initSign(myKeys.getPrivate());

		byte[] proxyNonceDigest = nonceHash.digest(nonce);
		SecureRandom r = new SecureRandom();
		byte[] serverNonce = ByteBuffer.allocate(4).putInt(r.nextInt()).array();
		n2 = serverNonce;
		
		byte[] publicKey = ByteBuffer.allocate(PUBLIC_LEN).put(myKeys.getPublic().getEncoded()).array();
		
		System.arraycopy(publicKey, 0, sigInput, 0, PUBLIC_LEN);
		System.arraycopy(proxyNonceDigest, 0, sigInput, PUBLIC_LEN, SHA256_LEN);
		System.arraycopy(serverNonce, 0, sigInput, PUBLIC_LEN + SHA256_LEN, NONCE_LEN);
		signature.update(sigInput);

		byte[] signatureBytes = signature.sign();
		byte[] payload = new byte[SHA256_LEN + NONCE_LEN + PUBLIC_LEN + signatureBytes.length];
		System.arraycopy(SIG_SUITE.getBytes(), 0, data, 0, DIG_SIG_LEN);
		System.arraycopy(sigInput, 0, data, DIG_SIG_LEN, PUBLIC_LEN + NONCE_LEN + SHA256_LEN);
		System.arraycopy(signatureBytes, 0, data, DIG_SIG_LEN + PUBLIC_LEN + NONCE_LEN + SHA256_LEN,
				signatureBytes.length);

		mySigSuite = SIG_SUITE;
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
			SSPPacket packetToSend = createPacket(frame, frameLen, contentType, payloadType);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(packetToSend);
			oos.flush();
			res = baos.toByteArray();
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

	public byte[] respChallenge(byte[] data, SSPPacket ssp, String sigSuite) throws Exception {
		byte[] digSuite = ByteBuffer.allocate(DIG_SIG_LEN).put(data, 0, DIG_SIG_LEN).array();
		String digSuiteName = new String(digSuite,StandardCharsets.UTF_8);
		byte[] pubKey = ByteBuffer.allocate(PUBLIC_LEN).put(data,DIG_SIG_LEN,PUBLIC_LEN).array();
		X509EncodedKeySpec spec = new X509EncodedKeySpec(pubKey);
		String keyAlgo = getKeyAlgo(digSuiteName);
		KeyFactory kf = KeyFactory.getInstance(keyAlgo);
		pubKeyServer = kf.generatePublic(spec);
		mySigSuite = sigSuite;
	
		Signature s = Signature.getInstance(digSuiteName);
		s.initVerify((PublicKey) pubKeyServer);
		byte[] hashN1 = ByteBuffer.allocate(SHA256_LEN).put(data,DIG_SIG_LEN+PUBLIC_LEN,SHA256_LEN).array();
		byte[] serverNounce = ByteBuffer.allocate(NONCE_LEN).put(data,DIG_SIG_LEN+PUBLIC_LEN+SHA256_LEN,NONCE_LEN).array();
		int sigBlen = ssp.getPayloadSize() - (DIG_SIG_LEN+PUBLIC_LEN+SHA256_LEN+NONCE_LEN);
		byte[] sigBytes = ByteBuffer.allocate(sigBlen).put(data,DIG_SIG_LEN+PUBLIC_LEN+SHA256_LEN+NONCE_LEN, sigBlen).array();
		
		s.update(data, DIG_SIG_LEN, PUBLIC_LEN+SHA256_LEN+NONCE_LEN);
		s.verify(sigBytes);
		
		MessageDigest md = MessageDigest.getInstance(SHA256);
		md.update(n1);
		if(!MessageDigest.isEqual(md.digest(), hashN1))
			throw new Exception("Nounce1 is different");
		
		String keyAlgo2 = getKeyAlgo(sigSuite);
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgo2);
		keyGen.initialize(PUBLIC_LEN);
		myKeys = keyGen.generateKeyPair();
		Signature signature = Signature.getInstance(sigSuite);
		signature.initSign(myKeys.getPrivate());
		
		byte[] pubKeySigBytes = ByteBuffer.allocate(PUBLIC_LEN).put(myKeys.getPublic().getEncoded()).array(); 
		md = MessageDigest.getInstance(SHA256);
		byte[] hashedN2 = md.digest(serverNounce);
		
		byte[] nonce = ByteBuffer.allocate(4).putInt(r.nextInt()).array();
		n3 = nonce;
		byte[] myDHPub = ByteBuffer.allocate(PUBLIC_LEN).put(myDHKeyPair.getPublic().getEncoded()).array();
		
		byte[] signInput = new byte[SHA256_LEN+PUBLIC_LEN+NONCE_LEN];
		System.arraycopy(hashedN2, 0, signInput, 0, SHA256_LEN);
		System.arraycopy(nonce, 0, signInput,SHA256_LEN, NONCE_LEN);

		System.arraycopy(myDHPub, 0, signInput, SHA256_LEN+NONCE_LEN, PUBLIC_LEN);
		byte[] proxyDigSuite = ByteBuffer.allocate(DIG_SIG_LEN).put(sigSuite.getBytes()).array();
		
		signature.update(signInput);
		byte[] signBytes = signature.sign();
		byte[] payload = new byte[SHA256_LEN+NONCE_LEN+PUBLIC_LEN+PUBLIC_LEN+DIG_SIG_LEN+signBytes.length];
		System.arraycopy(proxyDigSuite, 0, payload, 0, DIG_SIG_LEN);
		System.arraycopy(pubKeySigBytes, 0, payload, DIG_SIG_LEN, PUBLIC_LEN);
		System.arraycopy(signInput, 0, payload, DIG_SIG_LEN+PUBLIC_LEN,SHA256_LEN+PUBLIC_LEN+NONCE_LEN);
		System.arraycopy(signBytes, 0, payload, DIG_SIG_LEN+PUBLIC_LEN+SHA256_LEN+PUBLIC_LEN+NONCE_LEN, signBytes.length);
		
		int payloadLen = payload.length;

		return preparePayload(payload, payloadLen, (byte)0x02, (byte)0x03);
	}

	private String getKeyAlgo(String digSuiteName) {
		String keyAlgo = digSuiteName.substring(digSuiteName.lastIndexOf("with"),digSuiteName.length()).replace("with", "").trim();
		if (keyAlgo.contains("/"))
			keyAlgo = keyAlgo.substring(0,keyAlgo.indexOf("/"));
		else if (keyAlgo.contains("ECDSA"))
			keyAlgo = keyAlgo.substring(0,keyAlgo.length()-3);
		return keyAlgo;
	}
	

	/**
	 * Creates a new SSPPacket ciphering the frame and converting at SSPPacket into
	 * a byte array (was ciphering after thread sleep now ciphering before)
	 * @param frame
	 * @param frameLen
	 * @return
	 */
	public byte[] cipherPayload(byte[] frame, int frameLen) {
		byte[] res = null;
		try {
			SSPPacket packetToSend = createPacket(frame, frameLen,(byte)0x01,(byte)0x01);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(packetToSend);
			oos.flush();
			res = baos.toByteArray();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return res;
	}

	public byte[] getKeyEstablish(SSPPacket ssp, byte[] buff) throws Exception {
		byte[] digSuite = ByteBuffer.allocate(DIG_SIG_LEN).put(buff, 0, DIG_SIG_LEN).array();
		String digSuiteName = new String(digSuite,StandardCharsets.UTF_8).trim();
		byte[] pubKey = ByteBuffer.allocate(PUBLIC_LEN).put(buff,DIG_SIG_LEN,PUBLIC_LEN).array();
		
		EncodedKeySpec spec = new X509EncodedKeySpec(pubKey);
		String keyAlgo = getKeyAlgo(digSuiteName);
		KeyFactory kf = KeyFactory.getInstance(keyAlgo);
		PublicKey publicKey = kf.generatePublic(spec);
			
		byte[] hashN2 = ByteBuffer.allocate(SHA256_LEN).put(buff,DIG_SIG_LEN+PUBLIC_LEN,SHA256_LEN).array();
		byte[] recN3 = ByteBuffer.allocate(NONCE_LEN).put(buff,DIG_SIG_LEN+PUBLIC_LEN+SHA256_LEN,NONCE_LEN).array();
		byte[] dhProxyKey = ByteBuffer.allocate(PUBLIC_LEN).put(buff,DIG_SIG_LEN+PUBLIC_LEN+SHA256_LEN+NONCE_LEN,PUBLIC_LEN).array();
		spec = new X509EncodedKeySpec(dhProxyKey);
		kf = KeyFactory.getInstance("DH");
		Key publicDHKey = kf.generatePublic(spec);
		
		byte[] sigBytes = new byte[ssp.getPayloadSize() - (DIG_SIG_LEN+PUBLIC_LEN+SHA256_LEN+NONCE_LEN+PUBLIC_LEN)];
		System.arraycopy(buff, DIG_SIG_LEN+PUBLIC_LEN+SHA256_LEN+NONCE_LEN+PUBLIC_LEN, sigBytes, 0, sigBytes.length);
		
		Signature s = Signature.getInstance(digSuiteName);
		s.initVerify(publicKey);
		s.update(buff, DIG_SIG_LEN+PUBLIC_LEN, PUBLIC_LEN+SHA256_LEN+NONCE_LEN);
		s.verify(sigBytes);
		
		MessageDigest md = MessageDigest.getInstance(SHA256);
		md.update(n2);
		if(!MessageDigest.isEqual(md.digest(), hashN2))
			throw new Exception("Nonce2 is different");
		
		myKeyAgree.doPhase(publicDHKey, true);
		secretBytes = myKeyAgree.generateSecret();
		
		secretKeyHS = ByteBuffer.allocate(16).put(secretBytes,0,16).array();
		setCipherSuite(secretBytes);
				
		md = MessageDigest.getInstance(SHA256);
		byte[] hashedN3 = md.digest(recN3);
		byte[] nonce = ByteBuffer.allocate(4).putInt(r.nextInt()).array();
		n4 = nonce;

		
		byte[] myDHPub = ByteBuffer.allocate(PUBLIC_LEN).put(myDHKeyPair.getPublic().getEncoded()).array();

		
		byte[] sealedEnv = new byte[NONCE_LEN+secretBytes.length];
		System.arraycopy(nonce, 0, sealedEnv, 0, NONCE_LEN);
		System.arraycopy(secretBytes, 0, sealedEnv, NONCE_LEN, secretBytes.length);
		
		Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		c.init(Cipher.ENCRYPT_MODE, publicKey);
		
		byte[] encSealedEnv = c.doFinal(sealedEnv);
			
		byte[] encSealedEnv2 = ByteBuffer.allocate(PUBLIC_CIPH_LEN).put(encSealedEnv).array();
		
		Signature mySign = Signature.getInstance("SHA512withRSA/PSS");
		mySign.initSign(myKeys.getPrivate());
		mySign.update(myDHPub);
		byte[] signed = mySign.sign();
		
		
		
		byte[] payload = new byte[PUBLIC_CIPH_LEN+SHA256_LEN+PUBLIC_LEN+DIG_SIG_LEN+signed.length];
		System.arraycopy(mySigSuite.getBytes(), 0, payload, 0, DIG_SIG_LEN);
	
		System.arraycopy(hashedN3, 0, payload, DIG_SIG_LEN, SHA256_LEN);
		System.arraycopy(myDHPub, 0, payload, DIG_SIG_LEN+SHA256_LEN, PUBLIC_LEN);
		System.arraycopy(encSealedEnv2, 0, payload, DIG_SIG_LEN+SHA256_LEN+PUBLIC_LEN, PUBLIC_CIPH_LEN);
		System.arraycopy(signed, 0, payload, DIG_SIG_LEN+SHA256_LEN+PUBLIC_LEN+PUBLIC_CIPH_LEN,signed.length);
		
		
		int payloadLen = DIG_SIG_LEN+SHA256_LEN+PUBLIC_LEN+PUBLIC_CIPH_LEN+signed.length;
		
		return preparePayload(payload, payloadLen, (byte)0x02, (byte)0x04);
	}
	
	private void setCipherSuite(byte[] secretBytes) {
		byte[] mac1Bytes = new byte[] {0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00};
		byte[] mac2Bytes = new byte[] {(byte)0x80,0x70,0x60,0x50,0x40,0x30,0x20,0x10,(byte)0x99,(byte)0x98,
				(byte)0x97,(byte)0x96,(byte)0x95,(byte)0x94,(byte)0x93,(byte)0x92};
		cipherSuite = "AES/CBC/PKCS5Padding";
		algorithm = cipherSuite.substring(0, cipherSuite.indexOf("/"));
		mac1 = "HmacSHA256";
		mac2 = "HmacSHA1";
		iv = ByteBuffer.allocate(16).put(secretBytes, 16, 16).array();
		sessionKey = new SecretKeySpec(ByteBuffer.allocate(32).put(secretBytes, 32, 32).array(), algorithm);
		if (!mac1.equals("NULL")) {
			noMAC = false;
			mac1Key = new SecretKeySpec(mac1Bytes, mac1);
		}
		mac2Key = new SecretKeySpec(mac2Bytes, mac2);
		ivSpec = new IvParameterSpec(iv);
		try {
			cipher = Cipher.getInstance(cipherSuite);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	

	public byte[] handShakeDone(byte[] data, SSPPacket ssp) throws Exception {
		byte[] digSuite = ByteBuffer.allocate(DIG_SIG_LEN).put(data, 0, DIG_SIG_LEN).array();
		String digSuiteName = new String(digSuite,StandardCharsets.UTF_8).trim();
		byte[] hashN3 = ByteBuffer.allocate(SHA256_LEN).put(data,DIG_SIG_LEN,SHA256_LEN).array();
		byte[] dhKey = ByteBuffer.allocate(PUBLIC_LEN).put(data,DIG_SIG_LEN+SHA256_LEN,PUBLIC_LEN).array();
		byte[] sealedEnv = ByteBuffer.allocate(PUBLIC_CIPH_LEN).put(data,DIG_SIG_LEN+SHA256_LEN+PUBLIC_LEN,PUBLIC_CIPH_LEN).array();
		int sigSize = ssp.getPayloadSize() - (DIG_SIG_LEN+SHA256_LEN+PUBLIC_LEN+PUBLIC_CIPH_LEN);
		byte[] sigBytes = ByteBuffer.allocate(sigSize).put(data,(DIG_SIG_LEN+SHA256_LEN+PUBLIC_LEN+PUBLIC_CIPH_LEN),sigSize).array();
		
		MessageDigest md = MessageDigest.getInstance(SHA256);
		byte[] hashKey = md.digest(n3);
		
		Signature s = Signature.getInstance(digSuiteName);
		s.initVerify((PublicKey) pubKeyServer);
		s.update(dhKey);
		s.verify(sigBytes);
		
		if(!MessageDigest.isEqual(hashKey, hashN3))
			throw new Exception("Nonce 3 not equal");
		
		Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		c.init(Cipher.DECRYPT_MODE, myKeys.getPrivate());
		byte[] decrypted = c.doFinal(sealedEnv);
		md = MessageDigest.getInstance(SHA256);
		byte[] nonce4 = ByteBuffer.allocate(4).put(decrypted,0,NONCE_LEN).array();
		md.update(nonce4);
		
		byte[] hashn4 = md.digest();
		
		byte[] secretBytes = ByteBuffer.allocate(PUBLIC_LEN).put(decrypted,NONCE_LEN,decrypted.length-NONCE_LEN).array();
		
		setCipherSuite(secretBytes);
		
		Cipher c2 = Cipher.getInstance("AES");
		byte[] secretKey = ByteBuffer.allocate(16).put(secretBytes,0,16).array();
		SecretKey sk = new SecretKeySpec(secretKey, 0, secretKey.length, "AES");
		c2.init(Cipher.ENCRYPT_MODE, sk);
		
		byte[] finish = "FINISHED".getBytes();
		byte[] payloadCiph = new byte[finish.length+SHA256_LEN];

		System.arraycopy(finish, 0, payloadCiph, 0,finish.length);
		System.arraycopy(hashn4, 0, payloadCiph, finish.length, SHA256_LEN);
		
		byte[] enc = c2.doFinal(payloadCiph);
		
		int payloadLen = enc.length;
		return preparePayload(enc, payloadLen, (byte)0x02, (byte)0x05);
	}

	public void confirmHandshake(SSPPacket ssp, byte[] buff) throws Exception {
		Cipher c1 = Cipher.getInstance("AES");
		SecretKey sk = new SecretKeySpec(secretKeyHS, 0, secretKeyHS.length, "AES");
		c1.init(Cipher.DECRYPT_MODE, sk);
		byte[] finalPayload = c1.doFinal(buff,0,ssp.getPayloadSize());
		String finish = new String(finalPayload,0,FINISH_LEN);
		byte[] hashn4 = ByteBuffer.allocate(SHA256_LEN).put(finalPayload,FINISH_LEN,SHA256_LEN).array();
		MessageDigest md = MessageDigest.getInstance(SHA256);
		byte[] h4 = md.digest(n4);

		if (!MessageDigest.isEqual(md.digest(n4),hashn4))
			throw new Exception("Nonce 4 was wrong");	
	}
}
