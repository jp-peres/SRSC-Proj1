package socket;

import java.io.ByteArrayInputStream;

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

import java.security.MessageDigest;

import java.security.NoSuchAlgorithmException;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.net.SocketAddress;

import java.util.Properties;
import java.util.Random;

import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;

import javax.crypto.IllegalBlockSizeException;

import javax.crypto.Mac;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SSPSockets extends DatagramSocket {

	private static String digits = "0123456789abcdef";
	private static final int ID_LENGTH = 6;
	private static final int NONCE_LENGTH = 4;
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
	
	public SSPSockets(SocketAddress sockAddr) throws SocketException {
		super(sockAddr);
	}
	
	public SSPSockets(String config) throws IOException {
		super();
		InputStream inputStream = null;
		try {
			inputStream = new FileInputStream(config);
		}
		catch (FileNotFoundException ex) {
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
		sessionKey = new SecretKeySpec(toByteArray(properties.getProperty("SESSION-KEY")), algorithm);

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
	
	public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();
        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;   
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }


	public byte[] helloPayload(String[] args, byte[] buffer)
			throws Exception {
		String helloString = "Hello";
        String PWDCS = args[2];
        String pwd = args[1];
        String proxyID = args[0];
        if (proxyID.length() != 5)
        	throw new Exception("ProxyID must be comprised of 5 characters.");
        String movie =  args[3];
        

        Random r = new Random();
        byte[] nounce = ByteBuffer.allocate(4).putInt(r.nextInt()).array();
        
        System.arraycopy(helloString.getBytes(), 0, buffer, 0, helloString.length());
        System.arraycopy(proxyID.getBytes(), 0, buffer, helloString.length(), proxyID.length());
        System.arraycopy(movie.getBytes(), 0, buffer, helloString.length() + proxyID.length(), movie.length());
        System.arraycopy(nounce, 0, buffer, helloString.length() + proxyID.length() + movie.length(), 4);
        System.arraycopy(PWDCS.getBytes(), 0, buffer, helloString.length() + proxyID.length() + movie.length() + 4, PWDCS.length());
       
        MessageDigest pwdHash = MessageDigest.getInstance("SHA256");
        pwdHash.update(pwd.getBytes());
        byte[] hashPass = pwdHash.digest();
        String hash = SSPSockets.toHex(hashPass,hashPass.length);
        
        byte[] hashInput = new byte[helloString.length() + proxyID.length() + movie.length() + 4];
        System.arraycopy(buffer, 0, hashInput, 0, hashInput.length);
        byte[] salt = new byte[] {0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae};
        int iterationCount = 2048;
        PBEKeySpec pbeSpec = new PBEKeySpec(hash.toCharArray());
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(PWDCS);
        Cipher cipher = Cipher.getInstance(PWDCS);
        Key skey = keyFact.generateSecret(pbeSpec);
        cipher.init(Cipher.ENCRYPT_MODE, skey, new PBEParameterSpec(salt, iterationCount));
        
        byte[] finalCipher = cipher.doFinal(hashInput, 0, hashInput.length);
        System.arraycopy(finalCipher, 0, buffer, helloString.length() + proxyID.length() + movie.length() + 4 + PWDCS.length(), finalCipher.length);
        
        int payloadLen = helloString.length() + proxyID.length() + movie.length() + 4 + PWDCS.length() + finalCipher.length;
        
        return preparePayload(buffer, payloadLen, (byte)0x02,(byte)0x01);
	}
	
	
	/**
	 * Creates a new SSPPacket ciphering the frame and converting at SSPPacket into
	 * a byte array (was ciphering after thread sleep now ciphering before)
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
			SSPPacket packetToSend = createPacket(frame, frameLen,contentType,payloadType);
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
		/*try {
			// string to byte[]
			// System.err.println("Incoming frame length: " + data.getLength());
			// String expected = new String(data.getData(),StandardCharsets.UTF_8);
			// System.err.println("Real frame:" + expected);
			//
			// packetToSend = createPacket(data.getData(), data.getLength());
			// ByteArrayOutputStream baos = new ByteArrayOutputStream(); ObjectOutputStream
			// oos = new ObjectOutputStream(baos); oos.writeObject(packetToSend);
			/7 oos.flush(); data.setData(baos.toByteArray());
			//
			// System.err.println("Data ciphered length: " + data.getLength());
			super.send(data);

		} catch (Exception ex) {
			ex.printStackTrace();
		}*/
		super.send(data);
	}

	@Override
	public synchronized void receive(DatagramPacket data) throws IOException {
			super.receive(data);
			/*ByteArrayInputStream bais = new ByteArrayInputStream(data.getData(), 0, data.getLength());
			ObjectInputStream ois = new ObjectInputStream(bais);
			// System.err.println("Expected frame length: "+ data.getLength());
			received = (SSPPacket) ois.readObject();
			
			if (received.getContentType()==0x01) {
			
			
				byte[] original = getFrame(received);
			// No UDP proxy o outro socket lia do buffer e nao do datagram packet logo ao
			// fazermos
			// setData estavamos a desreferenciar o buffer no outro lado.
				data.setData(original);
			// String expected = new String(original,StandardCharsets.UTF_8);
			// System.err.println("Decrypted frame: " + expected);
			// System.err.println("Expected frame length: "+ original.length);
			*/
	}

	private SSPPacket createPacket(byte[] payload, int payloadSize, byte contentType, byte payloadType) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, 
			ShortBufferException, BadPaddingException, InvalidAlgorithmParameterException {
		if (contentType == 0x01)
			return createSSPPacket(payload,payloadSize);
		else
			return new SSPPacket(payload,contentType,payloadType,payloadSize);
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

	public byte[] getFrame(SSPPacket p)
			throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			ShortBufferException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
			IOException, ClassNotFoundException {
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
			byte[] frameMsg = new byte[frameLen - (ID_LENGTH + NONCE_LENGTH)];
			// System.err.println("FrameMsg len: " + frameMsg.length);
			System.arraycopy(realFrame, ID_LENGTH + NONCE_LENGTH, frameMsg, 0, frameMsg.length);
			return frameMsg;
		}
	}
}
