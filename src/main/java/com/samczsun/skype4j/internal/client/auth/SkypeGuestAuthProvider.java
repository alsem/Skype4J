package com.samczsun.skype4j.internal.client.auth;

import com.eclipsesource.json.JsonObject;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.NotParticipatingException;
import com.samczsun.skype4j.exceptions.SkypeAuthenticationException;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.SkypeImpl;
import com.samczsun.skype4j.internal.Utils;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.time.Instant;

/**
 * @author a.semennikov
 */
public class SkypeGuestAuthProvider implements SkypeAuthProvider {

	private final String username;
	private final String chatId;
	private String actualUsername;
	private String skypeToken;
	private Instant skypeTokenExpiryTime;

	public SkypeGuestAuthProvider(String username, String chatId) {
		this.username = username;
		this.chatId = chatId;
	}

	@Override public String getPassword() {
		return null;
	}

	@Override public String getUsername() {
		if (actualUsername == null) {
			throw new IllegalStateException("Should not be called when login has not completed");
		}
		return actualUsername;
	}

	@Override public void auth(SkypeImpl skype)
			throws ConnectionException, SkypeAuthenticationException {
		JsonObject response = Endpoints.NEW_GUEST
				.open(skype)
				.as(JsonObject.class)
				.on(303, connection -> {
					throw new NotParticipatingException();
				})
				.expect(201, "While logging in")
				.header("csrf_token", "skype4j")
				.cookie("csrf_token", "skype4j")
				.post(new JsonObject()
						.add("name", this.username)
						.add("threadId", chatId)
						.add("shortId", "Skype4J")
						.add("flowId", "Skype4J"));
		skypeToken = response.get("skypeToken").asString();

		String[] splits = skypeToken.split("\\.");
		try {
			String decoded = new String(DatatypeConverter.parseBase64Binary(Utils.makeValidBase64(splits[1])), "UTF-8");
			JsonObject object = JsonObject.readFrom(decoded).asObject();
			this.actualUsername = object.get("skypeid").asString();
			this.skypeTokenExpiryTime = Instant.ofEpochSecond(object.get("exp").asLong());
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	@Override public String getSkypeToken() {
		return skypeToken;
	}

	@Override public Instant getSkypeTokenExpiryTime() {
		return skypeTokenExpiryTime;
	}
}
