package server;
/*
 * hjStreamServer.java 
 * Streaming server: streams video frames in UDP packets
 * for clients to play in real time the transmitted movies
 */

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.Random;

import socket.SSPSockets;

class hjStreamServer {
	
	private static final int ID_LENGTH = 6;
	private static final int NONCE_LENGTH = 4;
	
	static public void main( String []args ) throws Exception {
		if (args.length != 4)
		{
			System.out.println("Erro, usar: SSPStreamServer <movie> <ip-multicast-address> <port> <file>");
			System.out.println("        or: SSPStreamServer <movie> <ip-unicast-address> <port> <file>");
			System.exit(-1);
		}

		int size;
		int count = 0;
		long time;
		DataInputStream g = new DataInputStream( new FileInputStream(args[0]) );
		byte[] buff = new byte[4096];

		InetSocketAddress addr = new InetSocketAddress( args[1], Integer.parseInt(args[2]));
		SSPSockets s = new SSPSockets(args[3]);
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
		long t0 = System.nanoTime(); // tempo de referencia para este processo
		long q0 = 0;

		String name = args[0].substring(args[0].lastIndexOf("/") + 1);

		String nameB = (name.length()<ID_LENGTH) ? name : name.substring(0, ID_LENGTH);

		while ( g.available() > 0 ) {
			buff = new byte[4096];
			Random r = new Random();
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; // tempo de referencia no stream
			count += 1;

			byte[] nounce = ByteBuffer.allocate(4).putInt(r.nextInt()).array();
			System.arraycopy(nameB.getBytes(), 0, buff, 0, ID_LENGTH);
			System.arraycopy(nounce, 0, buff, ID_LENGTH, NONCE_LENGTH);
			g.readFully(buff, ID_LENGTH + NONCE_LENGTH, size);
			byte[] cipheredPayload = s.cipherPayload(buff, size + ID_LENGTH + NONCE_LENGTH);
			p.setData(cipheredPayload);
			p.setSocketAddress( addr );
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
			// send packet (with a frame payload)
			// Frames sent in clear (no encryption)
			s.send( p );
			System.out.print( "." );
		}
		g.close();
		s.close();
		System.out.println("DONE! all frames sent: "+count);
	}
}