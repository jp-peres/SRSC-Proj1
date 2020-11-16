package proxy;
/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import socket.SSPPacket;
import socket.SSPSockets;

class hjUDPproxy {
	public static void main(String[] args) throws Exception {
		InputStream inputStream = new FileInputStream("src/main/java/config.properties");
		if (inputStream == null) {
			System.err.println("Configuration file not found!");
			System.exit(1);
		}
		if (args.length != 4) {
			System.err.println("SHPUDPproxy <proxyId> <password> <pcbciphersuite> <movie>");
			System.exit(1);
		}
		
		Properties properties = new Properties();
		properties.load(inputStream);
		String proxyaddr = properties.getProperty("proxyaddr");
		String streamaddr = properties.getProperty("streamaddr");
		String destinations = properties.getProperty("localdelivery");
		
		SocketAddress inSocketAddress = parseSocketAddress(proxyaddr);
		SocketAddress addr = parseSocketAddress(streamaddr);
		
		Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s))
				.collect(Collectors.toSet());

		SSPSockets inSocket = new SSPSockets(inSocketAddress);
		DatagramSocket outSocket = new DatagramSocket();
		byte[] buffer = new byte[4 * 1024];

		byte[] receiveBuffer = new byte[4*1024];
		DatagramPacket receivePacket = new DatagramPacket(buffer, buffer.length);
		
		byte[] helloSSP = inSocket.helloPayload(args, buffer);
		
		String payloadCont = new String(helloSSP,StandardCharsets.UTF_8);
		System.out.println(payloadCont);
		
		System.out.println("HelloSSP len: "+helloSSP.length);
		
		System.arraycopy(helloSSP, 0, buffer, 0, helloSSP.length);
		
		System.out.println("buffer len: "+ buffer.length);
		DatagramPacket p = new DatagramPacket(buffer, helloSSP.length);
		p.setSocketAddress(addr);
        inSocket.send(p);
        inSocket.receive(receivePacket);
		ByteArrayInputStream bais = new ByteArrayInputStream(receivePacket.getData(), 0, receivePacket.getLength());
		ObjectInputStream ois = new ObjectInputStream(bais);
		SSPPacket ssp = (SSPPacket) ois.readObject();
		byte[] data = ssp.getPayload();
        System.out.println("here");
        
		
		while (true) {
			DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
			inSocket.receive(inPacket); // if remote is unicast
			System.out.print("*");
			for (SocketAddress outSocketAddress : outSocketAddressSet) {
				outSocket.send(new DatagramPacket(inPacket.getData(), inPacket.getLength(), outSocketAddress));
			}
		}	
	}
	

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}
