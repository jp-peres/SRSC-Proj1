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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import socket.SSPPacket;
import socket.SSPSockets;

class hjUDPproxy {
	private static final String SIG_SUITE = "SHA256withRSA/PSS";
	
	public static void main(String[] args) throws Exception {
		InputStream inputStream = new FileInputStream("config.properties");
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
		String proxyaddr = null;
		String streamaddr = null;
		String destinations = null;
		try {
			proxyaddr = properties.getProperty("proxyaddr");
			streamaddr = properties.getProperty("streamaddr");
			destinations = properties.getProperty("localdelivery");
		} catch(Exception ex) {
			System.err.println("Missing fields from config.properties: proxyaddr and streamaddr. Where remote is proxyaddr and streamaddr is the address for the server. ex: proxyaddr:localhost:9999 and streamaddr:localhost:8888");
		}
		SocketAddress inSocketAddress = parseSocketAddress(proxyaddr);
		SocketAddress addr = parseSocketAddress(streamaddr);
		
		Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s))
				.collect(Collectors.toSet());

		SSPSockets inSocket = new SSPSockets(inSocketAddress);
		DatagramSocket outSocket = new DatagramSocket();
		byte[] buffer = new byte[5 * 1024];

		byte[] receiveBuffer = new byte[5*1024];
		DatagramPacket receivePacket = new DatagramPacket(buffer, buffer.length);
		
		byte[] helloSSP = inSocket.helloPayload(args, buffer);
		
		String payloadCont = new String(helloSSP,StandardCharsets.UTF_8);
		
		System.arraycopy(helloSSP, 0, buffer, 0, helloSSP.length);
		
		DatagramPacket p = new DatagramPacket(buffer, helloSSP.length);
		p.setSocketAddress(addr);
        inSocket.send(p);
        inSocket.receive(receivePacket);
		ByteArrayInputStream bais = new ByteArrayInputStream(receivePacket.getData(), 0, receivePacket.getLength());
		ObjectInputStream ois = new ObjectInputStream(bais);
		SSPPacket ssp = (SSPPacket) ois.readObject();
		byte[] data = ssp.getPayload();
        
		byte[] sspResp = inSocket.respChallenge(data,ssp,SIG_SUITE);
		p.setData(sspResp);
		inSocket.send(p);
        inSocket.receive(receivePacket);
        bais = new ByteArrayInputStream(receivePacket.getData(), 0, receivePacket.getLength());
		ois = new ObjectInputStream(bais);
		ssp = (SSPPacket) ois.readObject();
		data = ssp.getPayload();
        
        byte[] sspDone = inSocket.handShakeDone(data,ssp);
		p.setData(sspDone);
		inSocket.send(p);
		SSPPacket sspreceived;
		byte[] original;
		while (true) {
			DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
			inSocket.receive(inPacket); // if remote is unicast
			bais = new ByteArrayInputStream(inPacket.getData(), 0, inPacket.getLength());
			ois = new ObjectInputStream(bais);
			sspreceived = (SSPPacket) ois.readObject();
			original = inSocket.getFrame(sspreceived);
			inPacket.setData(original);
			for (SocketAddress outSocketAddress : outSocketAddressSet) {
				outSocket.send(new DatagramPacket(inPacket.getData(), inPacket.getLength(), outSocketAddress));
			}
			System.out.print("*");
		}	
	}
	

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		String host = split[0];
		int port = Integer.parseInt(split[1]);
		return new InetSocketAddress(host, port);
	}
}
