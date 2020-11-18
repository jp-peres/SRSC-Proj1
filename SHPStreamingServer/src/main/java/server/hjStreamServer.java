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
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import socket.SSPPacket;
import socket.SSPSockets;

class hjStreamServer {

	private static final int MOVIE_ID_LEN = 30;
	private static final int NONCE_LEN = 4;
	private static final int PROXY_ID_LEN = 5;
	private static final int PBESUITE_LEN = 27;
	private static final int DIG_SIG_LEN = 17;
	private static final int PUBLIC_LEN = 2048;
	private static final int SHA256_LEN = 32;
	private static final int HELLO_LEN = 5;
	private static final int ID_LENGTH = 6;
	private static final String SIG_SUITE = "SHA512withRSA/PSS";
	private static final String SHA256 = "SHA-256";

	private int seqNumber = 1;

	static public void main(String[] args) throws Exception {
		if (args.length != 2) {
			System.out.println("Erro, usar: SHPStreamServer <server-ip:port> <proxy-ip:port>");
			System.exit(-1);
		}

		Map<String, String> accounts = new HashMap<String, String>();
		accounts.put("48320", "ccadd99b16cd3d200c22d6db45d8b6630ef3d936767127347ec8a76ab992c2ea");
		accounts.put("54449", "aea49802178d9b2ba8781b03a131b5523c8947200b74f6d28fd84e9ca1bdb379");

		int size;
		int count = 0;
		long time;
		byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae };
		int iterCount = 2048;

		byte[] buff = new byte[5 * 1024];
		SocketAddress serverAddress = parseSocketAddress(args[0]);
		SocketAddress addr = parseSocketAddress(args[1]);

		SSPSockets s = new SSPSockets(serverAddress);
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
		long t0 = System.nanoTime(); // tempo de referencia para este processo
		long q0 = 0;

		String movieName = null;

		boolean handshakeDone = false;
		DatagramPacket response = null;
		while (true) {
			s.receive(p);
			ByteArrayInputStream bais = new ByteArrayInputStream(p.getData(), 0, p.getLength());
			ObjectInputStream ois = new ObjectInputStream(bais);
			SSPPacket ssp = (SSPPacket) ois.readObject();
			byte[] data = ssp.getPayload();
			System.arraycopy(data, 0, buff, 0, data.length);
			if (ssp.getContentType() == 0x02) {
				switch (ssp.getPayloadType()) {
				case 0x01:
					byte[] challengePayload = s.getAuthChallenge(accounts, ssp, buff, SIG_SUITE);
					movieName = s.getMovieName();
					response = new DatagramPacket(challengePayload, challengePayload.length, addr);
					break;
				case 0x03:
					byte[] keySA = s.getKeyEstablish(ssp, buff);
					response = new DatagramPacket(keySA, keySA.length, addr);
					break;
				case 0x05:
					s.confirmHandshake(ssp, buff);
					handshakeDone = true;
					break;
				}
			}
			if (handshakeDone)
				break;
			s.send(response);
		}
		DataInputStream g = null;
		try {
			g = new DataInputStream(new FileInputStream("movies/"+movieName));
		}catch(Exception ex){
			System.out.println("Cannot find movie. Tipical filepath: movies/<moviename.dat>");
			System.exit(-1);
		}
		
		while (g.available() > 0) {
			buff = new byte[4096];
			Random r = new Random();
			size = g.readShort();
			time = g.readLong();
			if (count == 0) q0 = time;
			count += 1;
			// tempo de referencia no stream 
			byte[] nounce = ByteBuffer.allocate(4).putInt(r.nextInt()).array();
			System.arraycopy(movieName.getBytes(), 0, buff, 0, ID_LENGTH);
			System.arraycopy(nounce, 0, buff, ID_LENGTH, NONCE_LEN);
			g.readFully(buff, ID_LENGTH + NONCE_LEN, size);
			byte[] cipheredPayload = s.cipherPayload(buff, size + ID_LENGTH + NONCE_LEN);
			p.setData(cipheredPayload);
			p.setSocketAddress(addr);
			long t = System.nanoTime();
			Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));
			// send packet (with a frame payload) // Frames sent in clear (no encryption)
			s.send(p);
			System.out.print(".");
		}

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