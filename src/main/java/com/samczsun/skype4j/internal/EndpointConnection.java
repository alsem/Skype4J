package com.samczsun.skype4j.internal;

import com.eclipsesource.json.JsonValue;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.internal.utils.Encoder;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;

/**
 * @author a.semennikov
 */
public class EndpointConnection<E_TYPE> {
	private Class<E_TYPE> clazz = (Class<E_TYPE>) HttpURLConnection.class;
	private Endpoints endpoint;
	private SkypeImpl skype;
	private Object[] args;
	private Map<String, String> headers = new HashMap<>();
	private Map<String, String> cookies = new HashMap<>();
	private Map<Predicate<Integer>, Endpoints.UncheckedFunction<E_TYPE>> errors = new HashMap<>();
	private URL url;
	private String cause;
	private boolean dontConnect;
	private boolean redirect = true;

	EndpointConnection(Endpoints endpoint, SkypeImpl skype, Object[] args) {
		this.endpoint = endpoint;
		this.skype = skype;
		this.args = args;
		header("User-Agent",
				"Mozilla/5.0 (Windows NT 10; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36 Skype4J/"
						+ SkypeImpl.VERSION);
	}

	public EndpointConnection<E_TYPE> header(String key, String val) {
		this.headers.put(key, val);
		return this;
	}

	public EndpointConnection<E_TYPE> cookie(String key, String val) {
		this.cookies.put(key, val);
		return this;
	}

	public EndpointConnection<E_TYPE> cookies(Map<String, String> cookies) {
		this.cookies.putAll(cookies);
		return this;
	}

	public EndpointConnection<E_TYPE> on(int code, Endpoints.UncheckedFunction<E_TYPE> action) {
		return on(x -> x == code, action);
	}

	public EndpointConnection<E_TYPE> on(Predicate<Integer> check, Endpoints.UncheckedFunction<E_TYPE> result) {
		this.errors.put(check, result);
		return this;
	}

	public EndpointConnection<E_TYPE> expect(int code, String cause) {
		return expect(x -> x == code, cause);
	}

	public EndpointConnection<E_TYPE> expect(Predicate<Integer> check, String cause) {
		this.cause = cause;
		return on(check, (connection) -> Endpoints.convert(clazz, skype, connection));
	}

	public EndpointConnection<E_TYPE> noRedirects() {
		this.redirect = false;
		return this;
	}

	public <NEW_E_TYPE> EndpointConnection<NEW_E_TYPE> as(Class<NEW_E_TYPE> clazz) {
		this.clazz = (Class<E_TYPE>) clazz;
		return (EndpointConnection<NEW_E_TYPE>) this;
	}

	public EndpointConnection<E_TYPE> dontConnect() {
		this.dontConnect = true;
		return this;
	}

	public E_TYPE get() throws ConnectionException {
		return connect("GET", new byte[0]);
	}

	public E_TYPE delete() throws ConnectionException {
		return connect("DELETE", new byte[0]);
	}

	public E_TYPE post() throws ConnectionException {
		return connect("POST", new byte[0]);
	}

	public E_TYPE post(String data) throws ConnectionException {
		return connect("POST", data);
	}

	public E_TYPE post(JsonValue json) throws ConnectionException {
		return header("Content-Type", "application/json")
				.header("Accept", "application/json").connect("POST", json.toString());
	}

	public E_TYPE put() throws ConnectionException {
		return connect("PUT", new byte[0]);
	}

	public E_TYPE put(String data) throws ConnectionException {
		return connect("PUT", data);
	}

	public E_TYPE put(JsonValue json) throws ConnectionException {
		return header("Content-Type", "application/json").connect("PUT", json.toString());
	}

	public E_TYPE connect(String method, String data) throws ConnectionException {
		return this.connect(method, data != null ? data.getBytes(StandardCharsets.UTF_8) : new byte[0]);
	}

	public E_TYPE connect(String method, byte[] rawData) throws ConnectionException {
		if (!cookies.isEmpty()) {
			header("Cookie", serializeCookies(cookies));
		}
		if (endpoint.isRegTokenRequired()) {
			header("RegistrationToken", skype.getRegistrationToken());
		}
		if (endpoint.isSkypeTokenRequired()) {
			header("X-SkypeToken", skype.getSkypeToken());
		}

		if (this.redirect) {
			this.on(code -> (code >= 301 && code <= 303) || code == 307 || code == 308, connection -> {
				skype.updateCloud(connection.getHeaderField("Location"));
				this.url = new URL(connection.getHeaderField("Location"));
				return this.connect(method, rawData);
			});
		}
		for (Map.Entry<String, Endpoints.Provider<String>> provider : endpoint.providers().entrySet()) {
			header(provider.getKey(), provider.getValue().provide(skype));
		}
		HttpsURLConnection connection = null;
		try {
			if (this.url == null) { //todo could fail if cloud is updated?
				String surl = endpoint.url();
				this.url = fillRequestArgs(surl);
			}
			String PROXY_HOST = System.getProperty("skype.conn.proxy.host", "");
			String PROXY_PORT = System.getProperty("skype.conn.proxy.port", "");
			Boolean sslEnabled = !Boolean.parseBoolean(System.getProperty("skype.conn.proxy.ssl.disabled"));
			Proxy proxy = Proxy.NO_PROXY;

			if (!PROXY_HOST.isEmpty() && !PROXY_PORT.isEmpty()) {
				proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(PROXY_HOST,
						Integer.parseInt(PROXY_PORT)));
			}

			connection = (HttpsURLConnection) url.openConnection(proxy);
			connection.setRequestMethod(method);
			connection.setInstanceFollowRedirects(false);
			if (sslEnabled) {
				connection.setSSLSocketFactory(getUnsafeSslSocketFactory());
				connection.setHostnameVerifier((hostName, session) -> true);
			}
			for (Map.Entry<String, String> ent : headers.entrySet()) {
				connection.setRequestProperty(ent.getKey(), ent.getValue());
			}
			if (!method.equalsIgnoreCase("GET")) {
				connection.setDoOutput(true);
				if (rawData != null) {
					connection.getOutputStream().write(rawData);
				} else {
					connection.getOutputStream().write(new byte[0]);
				}
			}
			if (!this.dontConnect) {
				for (Map.Entry<Predicate<Integer>, Endpoints.UncheckedFunction<E_TYPE>> entry : errors.entrySet()) {
					if (entry.getKey().test(connection.getResponseCode())) {
						try {
							return entry.getValue().apply(connection);
						} catch (Throwable t) {
							Utils.sneakyThrow(t);
						}
					}
				}
				throw ExceptionHandler.generateException(cause == null ? this.url.toString() : cause, connection);
			} else if (HttpURLConnection.class.isAssignableFrom(clazz)) {
				return (E_TYPE) connection;
			} else {
				throw new IllegalArgumentException(
						"DontConnect requested but did not request cast to HttpURLConnection");
			}
		} catch (IOException e) {
			throw ExceptionHandler.generateException(cause, e);
		} finally {
			if (clazz != InputStream.class && clazz != HttpURLConnection.class) {
				if (connection != null) {
					connection.disconnect();
				}
			}
		}
	}

	private URL fillRequestArgs(String surl) throws MalformedURLException {
		if (endpoint.isLocationRequired()) {
			Object[] format = new Object[args.length + 1];
			format[0] = skype.getCloud();
			for (int i = 1; i < format.length; i++) {
				format[i] = args[i - 1].toString();
			}
			surl = String.format(surl, format);
		} else if (args.length > 0) {
			Object[] format = new Object[args.length];
			for (int i = 0; i < format.length; i++) {
				format[i] = args[i].toString();
			}
			surl = String.format(surl, args);
		}
		return new URL(surl);
	}

	private SSLSocketFactory getUnsafeSslSocketFactory() {
		try {
			// Create a trust manager that does not validate certificate chains
			final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				@Override
				public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
						throws CertificateException {
				}

				@Override
				public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
						throws CertificateException {
				}

				@Override
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}
			} };

			// Install the all-trusting trust manager
			final SSLContext sslContext = SSLContext.getInstance("SSL");
			sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
			// Create an ssl socket factory with our all-trusting manager
			return sslContext.getSocketFactory();
		} catch (NoSuchAlgorithmException | KeyManagementException e) {
			throw new RuntimeException(e);
		}
	}

	private String serializeCookies(Map<String, String> cookies) {
		StringBuilder result = new StringBuilder();
		for (Map.Entry<String, String> cookie : cookies.entrySet()) {
			result.append(Encoder.encode(cookie.getKey())).append("=").append(Encoder.encode(cookie.getValue()))
					.append(";");
		}
		return result.toString();
	}
}
