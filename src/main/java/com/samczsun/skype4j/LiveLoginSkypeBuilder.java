/*
 * Copyright 2016 Sam Sun <me@samczsun.com>
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.samczsun.skype4j;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import com.eclipsesource.json.JsonObject;

import com.samczsun.skype4j.exceptions.handler.ErrorHandler;
import com.samczsun.skype4j.internal.client.FullClient;
import com.samczsun.skype4j.internal.client.GuestClient;
import com.samczsun.skype4j.internal.client.LiveLoginHelper;
import com.samczsun.skype4j.internal.client.MSFTSkypeClient;

/**
 * This class is used to construct a new {@link Skype} instance.
 */
public class LiveLoginSkypeBuilder {

	private final String username;
	private final String password;

	private Set<String> resources = new HashSet<>();
	private List<ErrorHandler> errorHandlers = new ArrayList<>();
	private Logger customLogger;
	private String chatId;

	/**
	 * Construct a SkypeBuilder with the given username and password
	 *
	 * @param username The username
	 * @param password The password
	 */
	public LiveLoginSkypeBuilder(String username, String password) {
		this.username = username;
		this.password = password;
	}

	/**
	 * Subscribe to all known resources
	 *
	 * @return The same SkypeBuilder
	 */
	public LiveLoginSkypeBuilder withAllResources() {
		resources.addAll(Arrays
				.asList("/v1/users/ME/conversations/ALL/properties", "/v1/users/ME/conversations/ALL/messages",
						"/v1/users/ME/contacts/ALL", "/v1/threads/ALL"));
		return this;
	}

	/**
	 * Subscribe to a resource which has not been added into the API
	 *
	 * @param resource The resource to subscribe to
	 *
	 * @return The same SkypeBuilder
	 */
	public LiveLoginSkypeBuilder withResource(String resource) {
		resources.add(resource);
		return this;
	}

	/**
	 * Use a custom logger for this Skype instance
	 *
	 * @param logger The custom logger to use
	 *
	 * @return The same SkypeBuilder
	 */
	public LiveLoginSkypeBuilder withLogger(Logger logger) {
		this.customLogger = logger;
		return this;
	}

	/**
	 * Add an exception handler to handle exceptions
	 *
	 * @param errorHandler The exception handler
	 * @return The same SkypeBuilder
	 */
	public LiveLoginSkypeBuilder withExceptionHandler(ErrorHandler errorHandler) {
		this.errorHandlers.add(errorHandler);
		return this;
	}

	/**
	 * Join a particular chat as a guest. Will have no effect if a password is specified
	 *
	 * @param id The chat id
	 *
	 * @return The same SkypeBuilder
	 */
    public LiveLoginSkypeBuilder withChat(String id) {
        if (!id.startsWith("19:")) throw new IllegalArgumentException("Invalid chat id");
        if (password != null) throw new IllegalArgumentException("Not guest account");
		this.chatId = id;
		return this;
	}

	/**
	 * Build the Skype instance!
	 *
	 * @return The Skype instance
	 */
	public Skype build() {
		if (resources.isEmpty()) {
			throw new IllegalArgumentException("No resources selected");
		}

		if (password != null && !username.contains("@")) {
			return new FullClient(username, password, resources, customLogger, errorHandlers);

		} else if (chatId != null && !username.contains("@")) {
			return new GuestClient(username, chatId, resources, customLogger, errorHandlers);

		} else if (username.contains("@")) {

			JsonObject object;
			try {
				object = LiveLoginHelper.getXTokenObject(username, password);
				String skypeToken = object.get("skypetoken").asString();
				String skypeId = object.get("skypeid").asString();
				return new MSFTSkypeClient(skypeToken, skypeId, resources, customLogger, errorHandlers);
			} catch (Exception e) {
				throw new IllegalArgumentException("Bad response",e);
			}
		} else {
			throw new IllegalArgumentException("No chat specified");
		}
	}
}
