package com.samczsun.skype4j.internal.client.auth;

import com.eclipsesource.json.JsonObject;
import com.samczsun.skype4j.Skype;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.SkypeImpl;
import com.samczsun.skype4j.internal.Utils;
import com.samczsun.skype4j.internal.threads.ActiveThread;
import com.samczsun.skype4j.internal.utils.Encoder;

import java.net.HttpURLConnection;
import java.time.Duration;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author a.semennikov
 */
@SuppressWarnings("Duplicates")
public class SkypeRegistrationProvider {

	private String registrationToken;
	private Instant registrationTokenExpiry;
	private String endpointId;
	private ActiveThread activeThread;

	public Instant getRegistrationTokenExpiry() {
		return registrationTokenExpiry;
	}

	public void registerEndpoint(SkypeImpl skype, String skypeToken) throws ConnectionException {
		String newRegToken = null;

		while (newRegToken == null) {

			HttpURLConnection post = requestEndpoint(skype, skypeToken);

			String regTokenHead = post.getHeaderField("Set-RegistrationToken");
			String locationHead = post.getHeaderField("Location");

			if (locationHead != null) {
				Matcher m = Pattern.compile("(https://[^/]+/v1)/users/ME/endpoints(/%7B([a-z0-9\\-]+)%7D)?")
						.matcher(locationHead);
				if (m.matches()) {
					if (m.groupCount() == 3 && m.group(3) != null) {
						this.endpointId = "{" + m.group(3) + "}";
					}

					if (!m.group(1).equals(Endpoints.ENDPOINTS_URL.url())) {
						// Skype is requiring the use of a different hostname.
						//update cloud prefix to use in queries
						skype.updateCloud(locationHead);
						//Don't accept the token if present, we need to re-register first.
					}
				}
			}

			if (regTokenHead != null) {
				String[] splits = regTokenHead.split(";");
				this.registrationToken = splits[0];
				long expiresInMillis = Long.parseLong(splits[1].split("=")[1]);
				this.registrationTokenExpiry = Instant.ofEpochMilli(Duration.ofSeconds(expiresInMillis).toMillis());
				if (splits.length > 2) {
					this.endpointId = splits[2].split("=")[1];
					if (this.activeThread != null) {
						this.activeThread.kill();
						this.activeThread = null;
					}
					(activeThread = new ActiveThread(skype, Encoder.encode(endpointId))).start();
				}
			}
			newRegToken = this.registrationToken;
		}

		Endpoints.MESSAGINGSERVICE_URL
				.open(skype, Encoder.encode(endpointId))
				.expect(200, "While submitting messagingservice")
				.put(buildRegistrationObject());
	}

	protected JsonObject buildRegistrationObject() {
		JsonObject publicInfo = new JsonObject()
				.add("capabilities", "video|audio")
				.add("type", 1)
				.add("skypeNameVersion", "skype.com")
				.add("nodeInfo", "")
				.add("version", Skype.VERSION);
		JsonObject privateInfo = new JsonObject()
				.add("epname", "Skype4J");
		JsonObject registrationObject = new JsonObject()
				.add("id", "messagingService")
				.add("type", "EndpointPresenceDoc")
				.add("selfLink", "uri")
				.add("publicInfo", publicInfo)
				.add("privateInfo", privateInfo);
		return registrationObject;
	}

	private HttpURLConnection requestEndpoint(SkypeImpl skype, String skypeToken)
			throws ConnectionException {
		return Endpoints.ENDPOINTS_URL.open(skype)
				.noRedirects()
				.on(301, (connection) -> followRedirectToRegisteredEndpoint(skype, skypeToken))
				.expect(code -> code == 201, "While registering endpoint")
				.header("Authentication", "skypetoken=" + skypeToken)
				.header("LockAndKey", Utils.generateChallengeHeader())
				.header("BehaviorOverride", "redirectAs404")
				.post(new JsonObject().add("endpointFeatures", "Agent"));
	}

	private HttpURLConnection followRedirectToRegisteredEndpoint(SkypeImpl skype, String skypeToken)
			throws ConnectionException {
		return Endpoints
				.custom(Endpoints.ENDPOINTS_URL.url() + "/" + Encoder.encode(endpointId), skype)
				.expect(200, "While registering endpoint")
				.header("Authentication", "skypetoken=" + skypeToken)
				.header("LockAndKey", Utils.generateChallengeHeader())
				.put(new JsonObject().add("endpointFeatures", "Agent"));
	}

	public String getRegistrationToken() {
		return registrationToken;
	}
}
