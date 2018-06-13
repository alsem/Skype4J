package com.samczsun.skype4j.internal.client;

import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.InvalidCredentialsException;
import com.samczsun.skype4j.exceptions.NotParticipatingException;
import com.samczsun.skype4j.exceptions.SkypeAuthenticationException;
import com.samczsun.skype4j.exceptions.handler.ErrorHandler;
import com.samczsun.skype4j.exceptions.handler.ErrorSource;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.SkypeThreadFactory;
import com.samczsun.skype4j.internal.client.auth.SkypeAuthProvider;
import com.samczsun.skype4j.internal.client.auth.SkypeLiveAuthProvider;
import com.samczsun.skype4j.internal.threads.AuthenticationChecker;
import com.samczsun.skype4j.internal.threads.ServerPingThread;
import com.samczsun.skype4j.internal.utils.UncheckedRunnable;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class MSFTSkypeClient extends FullClient {

	private SkypeAuthProvider authProvider;

	public MSFTSkypeClient(String userName, String password,
			Set<String> resources, Logger customLogger,
			List<ErrorHandler> errorHandlers) {
		super(userName, password, resources, customLogger, errorHandlers);
		this.authProvider = new SkypeLiveAuthProvider(userName, password);
	}

	@Override protected SkypeAuthProvider getAuthProvider() {
		return authProvider;
	}

	@Override
	public void login() throws ConnectionException, SkypeAuthenticationException {

		getAuthProvider().auth(this);
		Endpoints.ELIGIBILITY_CHECK.open(this, new Object[0])
				.expect(200, "You are not eligible to use Skype for Web!");
		loggedIn.set(true);

		loadAllContacts();
		getRegtokenProvider().registerEndpoint(this, getSkypeToken());

		if (this.serverPingThread != null) {
			this.serverPingThread.kill();
			this.serverPingThread = null;
		}

		if (this.activeThread != null) {
			this.activeThread.kill();
			this.activeThread = null;
		}

		if (this.reauthThread != null) {
			this.reauthThread.kill();
			this.reauthThread = null;
		}

		if (this.scheduler != null) {
			this.scheduler.shutdownNow();

			while (true) {
				if (!this.scheduler.isTerminated()) {
					continue;
				}
			}
		}

		this.shutdownThread = Executors.newSingleThreadExecutor(new SkypeThreadFactory(this, "Shutdown"));
		this.scheduler = Executors.newFixedThreadPool(4, new SkypeThreadFactory(this, "Poller"));
		(this.serverPingThread = new ServerPingThread(this)).start();
		(this.reauthThread = new AuthenticationChecker(this)).start();
	}

	// I override this for high-level login stuff
	@Override
	public void reAuthenticate() throws ConnectionException, InvalidCredentialsException,
			SkypeAuthenticationException {
		doShutdown();
		login();

		if (subscribed.get())
			subscribe();
	}
}