package com.samczsun.skype4j.internal.client.auth;

import com.eclipsesource.json.JsonObject;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.SkypeAuthenticationException;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.SkypeImpl;
import com.samczsun.skype4j.internal.utils.Encoder;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Standard authentication using Skype API endpoint
 *
 * @author a.semennikov
 */
public class SkypeApiAuthProvider implements SkypeAuthProvider {
	private String skypeToken = null;
	private Instant skypeTokenExpiry = null;
	private String username;
	private String password;

	public SkypeApiAuthProvider(String username, String password) {
		this.username = username;
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
		Map<String, String> data = new HashMap<>();
		data.put("scopes", "client");
		data.put("clientVersion", "0/7.4.85.102/259/");
		data.put("username", username.toLowerCase());
		data.put("passwordHash", hash(username, password));
		JsonObject loginData = Endpoints.LOGIN_URL.open(skype).as(JsonObject.class)
				.expect(200, "While logging in")
				.post(Encoder.encode(data));

		if (loginData.get("skypetoken") == null) {
			throw new SkypeAuthenticationException(
					"Couldn't retrieve Skype token from response for user %s" + username);
		}
		this.skypeToken = loginData.get("skypetoken").asString();

		if (loginData.get("expiresIn") != null) {
			long expiresInMillis = loginData.get("expiresIn").asLong();
			skypeTokenExpiry = Instant.now().plus(Duration.ofSeconds(expiresInMillis));
		}

	}

	@Override public String getSkypeToken() {
		return skypeToken;
	}

	@Override public Instant getSkypeTokenExpiryTime() {
		return skypeTokenExpiry;
	}

	private String hash(String username, String password) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			byte[] encodedMD = messageDigest
					.digest(String.format("%s\nskyper\n%s", username.toLowerCase(), password)
							.getBytes(StandardCharsets.UTF_8));
			return DatatypeConverter.printBase64Binary(encodedMD);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

}
