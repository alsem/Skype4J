package com.samczsun.skype4j.internal.client.auth;

import com.eclipsesource.json.JsonObject;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.SkypeAuthenticationException;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.SkypeImpl;
import com.samczsun.skype4j.internal.utils.Encoder;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.jsoup.select.Elements;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * @author a.semennikov
 */
@SuppressWarnings("Duplicates") public class SkypeLive2AuthProvider implements SkypeAuthProvider {
	private String username;
	private String password;
	private String skypeToken;
	private Instant skypeTokenExpiryTime;

	public SkypeLive2AuthProvider(String username, String password) {
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
		try {
			JsonObject params = getParams(skype);
			String t = sendCredentials(skype, username, password, params);
			getToken(skype, t);
		} catch (Exception e) {
			throw new SkypeAuthenticationException("Failed to get skype token", e);
		}
	}

	private JsonObject getParams(SkypeImpl skype) throws ConnectionException, SkypeAuthenticationException,
			IOException {

		HttpURLConnection get = Endpoints
				.custom("https://login.skype.com/login/oauth/microsoft?client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com",
						skype)
				.expect(200, "While getting handshake params")
				.get();
		String result = new BufferedReader(new InputStreamReader(get.getInputStream()))
				.lines().collect(Collectors.joining("\n"));
		Matcher m = Pattern.compile("<input.*type=\"hidden\".*name=\"PPFT\".*value=\"(.*)\">").matcher(result);
		if (!m.find()) {
			throw new SkypeAuthenticationException("Couldn't retrieve PPFT from login form");
		}
		String ppftReg = m.group(1);

		Map<String, List<String>> headerFields = get.getHeaderFields();
		List<String> cookieHeader = headerFields.get("Set-Cookie");
		List<HttpCookie> cookie = new ArrayList<>();
		for (String s : cookieHeader) {
			cookie.addAll(HttpCookie.parse(s));
		}

		String MSPRequ = null;
		String MSPOK = null;

		for (HttpCookie httpCookie : cookie) {
			if (httpCookie.getName().equals("MSPRequ")) {
				MSPRequ = httpCookie.getValue();
			}
			if (httpCookie.getName().equals("MSPOK")) {
				MSPOK = httpCookie.getValue();
			}
		}

		if (MSPRequ == null || MSPOK == null) {
			throw new SkypeAuthenticationException("Couldn't retrieve MSPRequ/MSPOK cookies");
		}

		return new JsonObject()
				.add("MSPRequ", MSPRequ)
				.add("MSPOK", MSPOK)
				.add("PPFT", ppftReg);
	}

	private String sendCredentials(SkypeImpl skype, String username, String password, JsonObject params) {
		try {
			Map<String, String> cookies = new HashMap<>();
			if (skypeToken != null) {
				cookies.put("refresh-token", skypeToken);
			}
			cookies.put("MSRequ", params.get("MSPRequ").asString());
			cookies.put("MSPOK", params.get("MSPOK").asString());
			cookies.put("CkTst", String.valueOf(Instant.now().toEpochMilli()));

			HttpURLConnection get = Endpoints.custom("https://login.live.com/ppsecure/post.srf?%s", skype,
					"wa=wsignin1.0"
							+ "&wp=MBI_SSL"
							+ "&wreply=https://lw.skype.com/login/oauth/proxy?client_id=578134&site_name=lw.skype.com&redirect_uri=https%3A%2F%2Fweb.skype.com%2F")
					.expect(code -> code == 200 || code == 201, "While logging in")
					.cookies(cookies)
					.post(new JsonObject()
							.add("login", username)
							.add("passwd", password)
							.add("PPFT", params.get("PPFT").asString()));
			String result = new BufferedReader(new InputStreamReader(get.getInputStream()))
					.lines().collect(Collectors.joining("\n"));
			Document doc = Parser.htmlParser().parseInput(result, "");

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
//		data.put("t", t);
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

	@Override public String getSkypeToken() {
		return skypeToken;
	}

	@Override public Instant getSkypeTokenExpiryTime() {
		return skypeTokenExpiryTime;
	}
}
