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

package com.samczsun.skype4j.internal.client;

import com.eclipsesource.json.JsonArray;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import com.samczsun.skype4j.chat.GroupChat;
import com.samczsun.skype4j.events.contact.ContactRequestEvent;
import com.samczsun.skype4j.exceptions.ChatNotFoundException;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.InvalidCredentialsException;
import com.samczsun.skype4j.exceptions.SkypeAuthenticationException;
import com.samczsun.skype4j.exceptions.handler.ErrorHandler;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.ExceptionHandler;
import com.samczsun.skype4j.internal.SkypeImpl;
import com.samczsun.skype4j.internal.client.auth.SkypeApiAuthProvider;
import com.samczsun.skype4j.internal.client.auth.SkypeAuthProvider;
import com.samczsun.skype4j.internal.client.auth.SkypeRefreshAuthProvider;
import com.samczsun.skype4j.internal.participants.info.ContactImpl;
import com.samczsun.skype4j.internal.participants.info.ContactRequestImpl;
import com.samczsun.skype4j.participants.info.Contact;

import java.net.HttpURLConnection;
import java.text.MessageFormat;
import java.text.ParseException;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FullClient extends SkypeImpl {
	private static final Pattern URL_PATTERN = Pattern.compile("threads/(.*)", Pattern.CASE_INSENSITIVE);

	private SkypeAuthProvider authProvider;
	private SkypeRefreshAuthProvider refreshAuthProvider;

	public FullClient(String username, String password, Set<String> resources, Logger customLogger,
			List<ErrorHandler> errorHandlers) {
		super(resources, customLogger, errorHandlers);
		this.authProvider = new SkypeApiAuthProvider(username, password);
		this.refreshAuthProvider = new SkypeRefreshAuthProvider(username, password);
	}

	@Override protected SkypeAuthProvider getAuthProvider() {
		return authProvider;
	}

	@Override
	public void login() throws InvalidCredentialsException, ConnectionException, SkypeAuthenticationException {
		getAuthProvider().auth(this);

		HttpURLConnection asmResponse = getAsmToken();

		this.loggedIn.set(true);
		loadAllContacts();
		getContactRequests(false);
		getRegtokenProvider().registerEndpoint(this, getSkypeToken());
		super.login();
	}

	@Override public void reAuthenticate()
			throws ConnectionException, InvalidCredentialsException, SkypeAuthenticationException {
		//todo: keep subscribed until reauth is finished so events aren't lost
		doShutdown();
		login();
		System.out.println(MessageFormat.format("{0}: Relogin successful", Instant.now().toString()));
		if (subscribed.get()) {
			subscribe();
		}
	}

	@Override
	public void logout() throws ConnectionException {
		Endpoints.LOGOUT_URL
				.open(this)
				.noRedirects()
				.expect(code -> (code >= 301 && code <= 303) || code == 307 || code == 308, "While logging out")
				.cookies(cookies)
				.get();
		shutdown();
	}

	@Override
	public void loadAllContacts() throws ConnectionException {
		JsonObject object = Endpoints.GET_ALL_CONTACTS
				.open(this, getUsername(), "default")
				.as(JsonObject.class)
				.expect(200, "While loading contacts")
				.get();
		for (JsonValue value : object.get("contacts").asArray()) {
			JsonObject obj = value.asObject();
			if (obj.get("suggested") == null || !obj.get("suggested").asBoolean()) {
				if (!allContacts.containsKey(obj.get("id").asString())) {
					this.allContacts.put(obj.get("id").asString(), new ContactImpl(this, obj));
				}
			}
		}
	}

	@Override
	public void getContactRequests(boolean isRegisteredEndpoint) throws ConnectionException {
		JsonObject array = Endpoints.GET_CONTACT_REQUESTS
				.open(this, getUsername()).as(JsonObject.class)
				.expect(200, "While loading contact requests").get();

		JsonArray inviteList = array.get("invite_list").asArray();
		for (JsonValue jsonValue : inviteList) {
			JsonObject inviteObject = jsonValue.asObject();

			String sender = inviteObject.get("mri").asString();

			Optional<JsonObject> lastInvite = inviteObject.get("invites").asArray().values().stream()
					.map(JsonValue::asObject).max(Comparator.comparing(o -> o.get("time").asString()));

			if (lastInvite.isPresent()) {
				String time = lastInvite.get().get("time").asString();
				String message = lastInvite.get().get("message").asString();
				try {
					Contact.ContactRequest request = new ContactRequestImpl(time, sender, message, this);

					if (this.allContactRequests.add(request)) {
						ContactRequestEvent event = new ContactRequestEvent(request);
						getEventDispatcher().callEvent(event);
					}
				} catch (ParseException e) {
					getLogger().log(Level.WARNING, "Could not parse date for contact request", e);
				}
			}
		}
		updateContactList();
	}

	@Override
	public void updateContactList() throws ConnectionException {
		JsonObject obj = Endpoints.GET_ALL_CONTACTS
				.open(this, getUsername(), "notification")
				.as(JsonObject.class)
				.expect(200, "While loading contacts")
				.get();
		for (JsonValue value : obj.get("contacts").asArray()) {
			if (value.asObject().get("suggested") == null || !value.asObject().get("suggested").asBoolean()) {
				String id = value.asObject().get("id").asString();
				ContactImpl impl = (ContactImpl) allContacts.get(id);
				if (impl == null)
					impl = (ContactImpl) loadContact(id);
				impl.update(value.asObject());
			}
		}
	}

	@Override
	public GroupChat createGroupChat(Contact... contacts) throws ConnectionException {
		JsonObject obj = new JsonObject();
		JsonArray allContacts = new JsonArray();
		allContacts.add(new JsonObject().add("id", "8:" + this.getUsername()).add("role", "Admin"));
		for (Contact contact : contacts) {
			allContacts.add(new JsonObject().add("id", "8:" + contact.getUsername()).add("role", "User"));
		}
		obj.add("members", allContacts);
		HttpURLConnection con = Endpoints.THREAD_URL
				.open(this)
				.as(HttpURLConnection.class)
				.expect(201, "While creating group chat")
				.post(obj);
		String url = con.getHeaderField("Location");
		Matcher chatMatcher = URL_PATTERN.matcher(url);
		if (chatMatcher.find()) {
			String id = chatMatcher.group(1);
			try {
				return (GroupChat) this.getOrLoadChat(id);
			} catch (ChatNotFoundException e) {
				throw new RuntimeException(e);
			}
		} else {
			throw ExceptionHandler.generateException("No chat location", con);
		}
	}

}
