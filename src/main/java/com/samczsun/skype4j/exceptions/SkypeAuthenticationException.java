package com.samczsun.skype4j.exceptions;

/**
 * @author a.semennikov
 */
public class SkypeAuthenticationException extends SkypeException {
	private static final long serialVersionUID = -1916850559014704215L;

	public SkypeAuthenticationException(String message) {
		super(message);
	}

	public SkypeAuthenticationException(String message, Exception e) {
		super(message, e);
	}
}
