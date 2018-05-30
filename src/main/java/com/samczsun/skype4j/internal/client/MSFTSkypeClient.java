package com.samczsun.skype4j.internal.client;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.InvalidCredentialsException;
import com.samczsun.skype4j.exceptions.NotParticipatingException;
import com.samczsun.skype4j.exceptions.handler.ErrorHandler;
import com.samczsun.skype4j.exceptions.handler.ErrorSource;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.SkypeThreadFactory;
import com.samczsun.skype4j.internal.threads.AuthenticationChecker;
import com.samczsun.skype4j.internal.threads.ServerPingThread;
import com.samczsun.skype4j.internal.utils.UncheckedRunnable;

public class MSFTSkypeClient extends FullClient {
	public MSFTSkypeClient(String skypeToken, String userName,
			Set<String> resources, Logger customLogger,
			List<ErrorHandler> errorHandlers) {
		super(userName, null, resources, customLogger, errorHandlers);

		setSkypeToken(skypeToken);
	}

	@Override
	public void login() throws ConnectionException {
		List<UncheckedRunnable> tasks = new ArrayList<>();

		tasks.add(this::loadAllContacts);
		tasks.add(() -> this.getContactRequests(false));
		tasks.add(this::registerEndpoint);
		tasks.add(() -> Endpoints.ELIGIBILITY_CHECK.open(this, new Object[0])
				.expect(200, "You are not eligible to use Skype for Web!").get());
		try {
			ExecutorService executorService = Executors.newFixedThreadPool(4);
			tasks.forEach(executorService::submit);
			executorService.shutdown();
			executorService.awaitTermination(1, TimeUnit.DAYS);

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
		} catch (InterruptedException e) {
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