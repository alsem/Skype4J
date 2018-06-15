package com.samczsun.skype4j.internal.client;

import com.samczsun.skype4j.LiveLoginSkypeBuilder;
import com.samczsun.skype4j.Skype;
import com.samczsun.skype4j.events.EventHandler;
import com.samczsun.skype4j.events.Listener;
import com.samczsun.skype4j.events.chat.message.MessageReceivedEvent;
import com.samczsun.skype4j.exceptions.ChatNotFoundException;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.InvalidCredentialsException;
import com.samczsun.skype4j.exceptions.NotParticipatingException;
import com.samczsun.skype4j.exceptions.SkypeAuthenticationException;

import java.time.Duration;
import java.time.Instant;
import java.util.Scanner;
import java.util.logging.Logger;

/**
 * @author a.semennikov
 */
public class EntryPoint implements Runnable {
	private static Logger logger = Logger.getLogger(EntryPoint.class.getName());
	static boolean quit = false;
	Scanner sc = new Scanner(System.in);

	/**
	 * @param args the command line arguments
	 */
	public static void main(String[] args)
			throws InterruptedException, ConnectionException, NotParticipatingException, InvalidCredentialsException,
			SkypeAuthenticationException {
		String username = args[0];
		String password = args[1];
		Skype skype = new LiveLoginSkypeBuilder(username, password).withAllResources()
				.withLogger(logger).build();
		skype.login();
		skype.getEventDispatcher().registerListener(new Listener() {

			@EventHandler
			public void onMessageReceived(MessageReceivedEvent event) throws ConnectionException {
				event.getChat().sendMessage("You typed: " + event.getMessage());
			}

		});
		// TODO code application logic here
		Thread mt = new Thread(new EntryPoint());
		mt.start();

		System.out.println("press Q THEN ENTER to terminate");

		while (true) {
			mt.sleep(Duration.ofSeconds(10).toMillis());
			if (quit) {
				skype.logout();
				break;
			}
//			System.out.println("hello buddy");
		}
		System.out.println("It is broken!");
	}

	@Override
	public void run() {
		String msg = "";
		while (!(msg.equals("Q"))) {
			try {
				msg = sc.nextLine();
			} catch (Exception e) {
			}
		}
		quit = true;
	}
}
