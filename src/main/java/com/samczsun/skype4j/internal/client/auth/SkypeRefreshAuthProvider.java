package com.samczsun.skype4j.internal.client.auth;

import com.eclipsesource.json.JsonObject;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.SkypeAuthenticationException;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.SkypeImpl;
import com.samczsun.skype4j.internal.Utils;
import com.samczsun.skype4j.internal.utils.Encoder;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.jsoup.select.Elements;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Refreshing skype authentication token. Applicable only for Skype old-fashioned accounts
 * @author a.semennikov
 */
public class SkypeRefreshAuthProvider implements SkypeAuthProvider {
	private final String username;
	private final String password;
	private String skypeToken;
	private Instant skypeTokenExpiryTime;

	public SkypeRefreshAuthProvider(String username, String password) {
		this.username = username;
		this.password = password;
	}

	@Override public void auth(SkypeImpl skype) throws ConnectionException, SkypeAuthenticationException {
		throw new IllegalStateException("Not yet coreectly working");
//		refreshToken(skype, skype.getSkypeToken());
	}

	private void refreshToken(SkypeImpl skype, String oldSkypeToken)
			throws ConnectionException, SkypeAuthenticationException {
		//Authentication dance
		String t = this.sendToken(skype, oldSkypeToken);
		this.getToken(skype, t);
	}

	private String sendToken(SkypeImpl skype, String skypeToken) throws ConnectionException {
		try {
			Map<String,String> cookies  = new HashMap<>();
			if (skypeToken != null) {
				cookies.put("refresh-token", skypeToken);
			}
			HttpURLConnection get = Endpoints.REFRESH_LOGIN_URL.open(skype)
					.expect(code -> code == 200 || code == 201, "While logging in")
					.cookies(cookies)
					.get();
			String result = new BufferedReader(new InputStreamReader(get.getInputStream()))
					.lines().collect(Collectors.joining("\n"));
			Document doc = Parser.htmlParser().parseInput(result,"");//Utils.parseJsonObject(jsonResp).get("content").asString();

			Element tField = doc.getElementById("t");
			if (tField == null) {
				throw new ConnectionException("Couldn't retrieve t field from login response",
						new IOException("no element with name \'t\'"));
			}
			return tField.val();
		} catch (Throwable e) {
			e.printStackTrace();
			return null;
		}
	}

	private void getToken(SkypeImpl skype, String t) throws ConnectionException {
		Map<String, String> data = new HashMap<>();
		data.put("t", t);
		data.put("client_id", "578134");
		data.put("oauthPartner", "999");
		data.put("site_name", "lw.skype.com");
		data.put("redirect_uri", "https://web.skype.com");
		JsonObject jsonResp = Endpoints.REFRESH_EXCHANGE_LOGIN_URL.open(skype)
				.expect(200, "While logging in")
				.as(JsonObject.class)
				.post(Encoder.encode(data));
		String content = jsonResp.get("content").asString();
		Document loginPage = Parser.xmlParser().parseInput(content, "");

		Element inputField = loginPage.select("input").first();
		Elements name = inputField.getElementsByTag("name");
		String skypetoken = name.select("skypetoken").first().val();
		String expiresIn = name.select("expires_in").first().val();

		if (skypetoken == null) {
			throw new ConnectionException("Couldn't retrieve t field from login response",
					new IOException("no element with name \'t\'"));
		}
		this.skypeToken = skypetoken;
		this.skypeTokenExpiryTime = Instant.now().plus(Duration.ofSeconds(Long.parseLong(expiresIn)));
	}

	@Override public String getPassword() {
		return password;
	}

	@Override public String getUsername() {
		return username;
	}

	public String getSkypeToken() {
		return skypeToken;
	}

	@Override public Instant getSkypeTokenExpiryTime() {
		return skypeTokenExpiryTime;
	}
}
