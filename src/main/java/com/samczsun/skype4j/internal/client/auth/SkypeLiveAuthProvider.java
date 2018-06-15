package com.samczsun.skype4j.internal.client.auth;

import com.eclipsesource.json.JsonObject;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.SkypeAuthenticationException;
import com.samczsun.skype4j.internal.SkypeImpl;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * @author a.semennikov
 */
public class SkypeLiveAuthProvider implements SkypeAuthProvider {

	private String username;
	private final String originalUsername;
	private String password;
	private String skypeToken;
	private Instant skypeTokenExpiryTime;

	public SkypeLiveAuthProvider(String username, String password) {
		this.username = username;
		this.originalUsername = username;
		this.password = password;
	}

	@Override public String getPassword() {
		return password;
	}

	@Override public String getUsername() {
		return username;
	}

	@Override public void auth(SkypeImpl skype)
			throws ConnectionException, SkypeAuthenticationException {
		try {
			JsonObject object = LiveLoginHelper.getXTokenObject(originalUsername, password);
			this.username = object.get("skypeid").asString();
			this.skypeToken = object.get("skypetoken").asString();
//			this.skypeTokenExpiryTime = Instant.now().plus(Duration.ofMinutes(5));
			this.skypeTokenExpiryTime = Instant.now().plus(Duration.ofSeconds(object.get("expiresIn").asLong()));
		} catch (Exception e) {
			throw new SkypeAuthenticationException("Failed to get skype token", e);
		}
	}

	@Override public String getSkypeToken() {
		return skypeToken;
	}

	@Override public Instant getSkypeTokenExpiryTime() {
		return skypeTokenExpiryTime;
	}
}
