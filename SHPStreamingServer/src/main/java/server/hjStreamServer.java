package server;
/*
 * hjStreamServer.java 
 * Streaming server: streams video frames in UDP packets
 * for clients to play in real time the transmitted movies
 */

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import socket.SSPPacket;
import socket.SSPSockets;

class hjStreamServer {

	private static final int MOVIE_ID_LENGTH = 6;
	private static final int NONCE_LENGTH = 4;

	private static final int PROXY_ID_LENGTH = 5;
	private static final int SUITE_LENGTH = 27;

	private static final int publick_Len = 2048;

	private static final int sha256_len = 256;

	private static MessageDigest nonceHash;



	private int seqNumber = 1;

	static public void main(String[] args) throws Exception {
		if (args.length != 3) {
			System.out.println(
					"Erro, usar: SHPStreamServer <server-ip:port> <proxy-multicast|unicast-address:port> <file>");
			System.exit(-1);
		}

		Map<String, String> accounts = new HashMap<String, String>();
		accounts.put("48320", "ccadd99b16cd3d200c22d6db45d8b6630ef3d936767127347ec8a76ab992c2ea");
		accounts.put("54449", "aea49802178d9b2ba8781b03a131b5523c8947200b74f6d28fd84e9ca1bdb379");

		nonceHash = MessageDigest.getInstance("SHA-256");

		int size;
		int count = 0;
		long time;
		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae };
		int iterCount = 2048;

		byte[] buff = new byte[6 * 4096];
		SocketAddress serverAddress = parseSocketAddress(args[0]);
		SocketAddress addr = parseSocketAddress(args[1]);

		SSPSockets s = new SSPSockets(serverAddress, args[2]);
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
		long t0 = System.nanoTime(); // tempo de referencia para este processo
		long q0 = 0;

		String name = args[0].substring(args[0].lastIndexOf("/") + 1);

		String nameB = (name.length() < MOVIE_ID_LENGTH) ? name : name.substring(0, MOVIE_ID_LENGTH);

		while (true) {
			s.receive(p);
			ByteArrayInputStream bais = new ByteArrayInputStream(p.getData(), 0, p.getLength());
			ObjectInputStream ois = new ObjectInputStream(bais);
			SSPPacket ssp = (SSPPacket) ois.readObject();
			byte[] data = ssp.getPayload();
			byte[] helloString = new byte[5];

			System.arraycopy(data, 0, helloString, 0, 5);
			String hello = new String(helloString, StandardCharsets.UTF_8);
			if (hello.equals("Hello")) {
				byte[] proxyID = new byte[5];
				System.arraycopy(data, 5, proxyID, 0, 5);
				String proxy = new String(proxyID);

				String hashPassword = accounts.get(proxy);

				if (hashPassword == null)
					throw new Exception("Proxy ID not found");

				byte[] movieNameBytes = new byte[30];
				System.arraycopy(data, 10, movieNameBytes, 0, 30);
				String movieName = new String(movieNameBytes).trim();

				// Get nounce (reusing movieNameBytes buffer)
				byte[] nonce = new byte[4];
				System.arraycopy(data, 40, nonce, 0, 4);
				int val = ByteBuffer.wrap(nonce).getInt();

				byte[] pbeSuiteBytes = new byte[SUITE_LENGTH];
				System.arraycopy(data, 44, pbeSuiteBytes, 0, SUITE_LENGTH);
				String pbeSuite = new String(pbeSuiteBytes).trim();

				int pbeBytesSize = ssp.getPayloadSize() - (44 + SUITE_LENGTH);
				byte[] pbeBytes = new byte[pbeBytesSize];
				System.arraycopy(data, 44 + SUITE_LENGTH, pbeBytes, 0, pbeBytesSize);
				
		        System.out.println("Transmited cipher: "+new String(pbeBytes,StandardCharsets.UTF_8));
		        System.out.println("Transmited cipher len: " + pbeBytes.length);
		        
		        Cipher cDec = s.getPBECipher(pbeSuite, hashPassword, Cipher.DECRYPT_MODE);
		        
				cDec.doFinal(pbeBytes);

				byte[] sigInput = new byte[2048 + 256 + 4];

				KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(2048, new SecureRandom());
				KeyPair keyPair = kpg.generateKeyPair();
				String sigcryptosuite = "SHA512withECDSA";
				System.arraycopy(sigcryptosuite.getBytes(), 0, buff, 0, sigcryptosuite.length());
				byte[] publicKey = keyPair.getPublic().getEncoded();
				System.arraycopy(publicKey, 0, buff, sigcryptosuite.length(), publicKey.length);

				nonceHash.update(nonce);
				byte[] nonceHashResponse = nonceHash.digest();
				System.arraycopy(nonceHashResponse, 0, buff, sigcryptosuite.length() + publicKey.length,
						nonceHashResponse.length);
				int serverNonce = new Random().nextInt();
				System.arraycopy(serverNonce, 0, buff,
						sigcryptosuite.length() + publicKey.length + nonceHashResponse.length, 4);
				byte[] inputSig = new byte[4 + publicKey.length + nonceHashResponse.length];
				System.arraycopy(buff, 0, inputSig, 0, inputSig.length);
				Signature signature = Signature.getInstance(sigcryptosuite);
				signature.initSign(keyPair.getPrivate(), new SecureRandom());
				signature.update(inputSig);
				byte[] signatureBytes = signature.sign();
				System.arraycopy(signatureBytes, 0, buff,
						sigcryptosuite.length() + publicKey.length + nonceHashResponse.length + 4,
						signatureBytes.length);
			}

			break;
		}

		DataInputStream g = new DataInputStream(new FileInputStream(args[0]));
		/*
		 * while ( g.available() > 0 ) { buff = new byte[4096]; Random r = new Random();
		 * size = g.readShort(); time = g.readLong(); if ( count == 0 ) q0 = time; //
		 * tempo de referencia no stream count += 1;
		 * 
		 * byte[] nounce = ByteBuffer.allocate(4).putInt(r.nextInt()).array();
		 * System.arraycopy(nameB.getBytes(), 0, buff, 0, ID_LENGTH);
		 * System.arraycopy(nounce, 0, buff, ID_LENGTH, NONCE_LENGTH); g.readFully(buff,
		 * ID_LENGTH + NONCE_LENGTH, size); byte[] cipheredPayload =
		 * s.cipherPayload(buff, size + ID_LENGTH + NONCE_LENGTH);
		 * p.setData(cipheredPayload); p.setSocketAddress( addr ); long t =
		 * System.nanoTime(); Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
		 * // send packet (with a frame payload) // Frames sent in clear (no encryption)
		 * s.send( p ); System.out.print( "." ); }
		 */
		g.close();
		s.close();
		System.out.println("DONE! all frames sent: " + count);
	}

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}