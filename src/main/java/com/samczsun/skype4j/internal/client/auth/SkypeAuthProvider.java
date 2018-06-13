package com.samczsun.skype4j.internal.client.auth;

import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.SkypeAuthenticationException;
import com.samczsun.skype4j.internal.SkypeImpl;

import java.time.Instant;

/**
 * @author a.semennikov
 */
public interface SkypeAuthProvider {
	/**
	 * current password
	 */
	String getPassword();

	/**
	 * current username
	 */
	String getUsername();

	void auth(SkypeImpl skype)
			throws ConnectionException, SkypeAuthenticationException;

	/**
	 * Skype token
	 */
	public String getSkypeToken();

	/**
	 * The time when skype token becames expired and we need to get new one
	 * @return {@link Instant Instant} of datetime
	 */
	Instant getSkypeTokenExpiryTime();
}
