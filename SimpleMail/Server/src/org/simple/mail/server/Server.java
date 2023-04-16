package org.simple.mail.server;

import java.io.IOException;
import java.net.ServerSocket;

public class Server {
	private final static int PORT = 5000;

	public static void main(String[] args) {
		System.out.println("Server running........");
		try (ServerSocket servSocket = new ServerSocket(PORT);) {
			while (true) {
				Runnable t = new ServerWorker(servSocket.accept());
				new Thread(t).start();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
