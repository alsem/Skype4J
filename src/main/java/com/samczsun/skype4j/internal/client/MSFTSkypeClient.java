package com.samczsun.skype4j.internal.client;

import com.samczsun.skype4j.exceptions.handler.ErrorHandler;
import com.samczsun.skype4j.internal.client.auth.SkypeAuthProvider;
import com.samczsun.skype4j.internal.client.auth.SkypeLiveAuthProvider;

import java.util.List;
import java.util.Set;
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

}