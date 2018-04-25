package com.samczsun.skype4j.internal.client;

import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.InvalidCredentialsException;
import com.samczsun.skype4j.exceptions.NotParticipatingException;
import com.samczsun.skype4j.exceptions.handler.ErrorHandler;
import com.samczsun.skype4j.exceptions.handler.ErrorSource;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.SkypeThreadFactory;
import com.samczsun.skype4j.internal.threads.AuthenticationChecker;
import com.samczsun.skype4j.internal.threads.ServerPingThread;

import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

public class MSFTSkypeClient extends FullClient {
	public MSFTSkypeClient(String skypeToken, String skypeId,
			Set<String> resources, Logger customLogger,
			List<ErrorHandler> errorHandlers) {
		super(skypeId, null, resources, customLogger, errorHandlers);

		setSkypeToken(skypeToken);
	}

	@Override
	public void login() {
		try {

			loadAllContacts();

			try {
				this.getContactRequests(false);
			} catch (Exception var2) {
				this.handleError(ErrorSource.UPDATING_CONTACT_LIST, var2, false);
			}

			try {
				this.registerWebSocket();
			} catch (Exception var2) {
				this.handleError(ErrorSource.REGISTERING_WEBSOCKET, var2, false);
			}

			registerEndpoint();

			Endpoints.ELIGIBILITY_CHECK.open(this, new Object[0])
									   .expect(200, "You are not eligible to use Skype for Web!").get();
			this.loggedIn.set(true);
			if (this.serverPingThread != null) {
				this.serverPingThread.kill();
				this.serverPingThread = null;
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
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	// I override this for high-level login stuff
	@Override
	public void reauthenticate() throws ConnectionException, InvalidCredentialsException, NotParticipatingException {
		doShutdown();

		login();

		if (subscribed.get())
			subscribe();
	}
}