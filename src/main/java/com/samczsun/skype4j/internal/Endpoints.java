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

package com.samczsun.skype4j.internal;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.imageio.ImageIO;

import com.eclipsesource.json.JsonArray;
import com.eclipsesource.json.JsonObject;

public class Endpoints {
    private static Map<Class<?>, Converter<?>> converters = new HashMap<>();

    static {
        converters.put(InputStream.class, HttpURLConnection::getInputStream);
        converters.put(HttpURLConnection.class, in -> in);
        converters.put(JsonObject.class, in -> Utils.parseJsonObject(in.getInputStream()));
        converters.put(JsonArray.class, in -> Utils.parseJsonArray(in.getInputStream()));
        converters.put(String.class, in -> StreamUtils.readFully(in.getInputStream()));
        converters.put(BufferedImage.class, in -> ImageIO.read(in.getInputStream()));
    }

    public static <T> T convert(Class<?> type, SkypeImpl skype, HttpURLConnection in) throws IOException {
        return (T) converters.get(type).convert(in);
    }

    public static final Provider<String> AUTHORIZATION = skype -> "skype_token " + skype.getSkypeToken();
    public static final Provider<String> COOKIE = skype -> "skypetoken_asm=" + skype.getSkypeToken();

	public static final Endpoints ACCEPT_CONTACT_REQUEST = new Endpoints(
			"https://contacts.skype.com/contacts/v2/users/%s/invites/%s/accept").skypetoken();
	public static final Endpoints DECLINE_CONTACT_REQUEST = new Endpoints(
			"https://contacts.skype.com/contacts/v2/users/%s/invites/%s/decline").skypetoken();

    public static final Endpoints GET_JOIN_URL = new Endpoints("https://api.scheduler.skype.com/threads").skypetoken();
    public static final Endpoints CHAT_INFO_URL = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/threads/%s/?view=msnp24Equivalent").cloud().regtoken();
    public static final Endpoints CONVERSATION_PROPERTY_SELF = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/users/ME/conversations/%s/properties?name=%s")
            .cloud()
            .regtoken();
    public static final Endpoints SEND_MESSAGE_URL = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/users/ME/conversations/%s/messages").cloud().regtoken();
    public static final Endpoints MODIFY_MEMBER_URL = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/threads/%s/members/%s").cloud().regtoken();
    public static final Endpoints CONVERSATION_PROPERTY_GLOBAL = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/threads/%s/properties?name=%s").cloud().regtoken();
    public static final Endpoints ADD_MEMBER_URL = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/threads/%s/members/8:%s").cloud().regtoken();
    public static final Endpoints LOGIN_URL = new Endpoints("https://api.skype.com/login/skypetoken");
    public static final Endpoints REFRESH_LOGIN_URL = new Endpoints("https://login.skype.com/login?client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com");
    public static final Endpoints REFRESH_EXCHANGE_LOGIN_URL =
            new Endpoints("https://login.skype.com/login/microsoft?client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com");
    public static final Endpoints PING_URL = new Endpoints("https://web.skype.com/api/v1/session-ping").skypetoken();
    public static final Endpoints TOKEN_AUTH_URL = new Endpoints("https://api.asm.skype.com/v1/skypetokenauth");
    public static final Endpoints LOGOUT_URL = new Endpoints(
            "https://login.skype.com/logout?client_id=578134&redirect_uri=https%3A%2F%2Fweb.skype.com&intsrc=client-_-webapp-_-production-_-go-signin");
    //called without regtoken or cloud
    public static final Endpoints ENDPOINTS_URL = new Endpoints(
            "https://client-s.gateway.messenger.live.com/v1/users/ME/endpoints");
    @Deprecated
    public static final Endpoints AUTH_REQUESTS_URL = new Endpoints(
            "https://api.skype.com/users/self/contacts/refreshToken-request").skypetoken();
    @Deprecated
    public static final Endpoints AUTHORIZE_CONTACT = new Endpoints(
            "https://api.skype.com/users/self/contacts/refreshToken-request/%s/accept").skypetoken();
    public static final Endpoints GET_CONTACT_REQUESTS = new Endpoints(
			"https://contacts.skype.com/contacts/v2/users/%s/invites").skypetoken();
    public static final Endpoints TROUTER_URL = new Endpoints("https://go.trouter.io/v2/a");
    public static final Endpoints POLICIES_URL = new Endpoints("https://prod.tpc.skype.com/v1/policies").skypetoken();
    public static final Endpoints REGISTRATIONS = new Endpoints(
            "https://prod.registrar.skype.com/v2/registrations").skypetoken();
    public static final Endpoints THREAD_URL = new Endpoints("https://%sclient-s.gateway.messenger.live.com/v1/threads")
            .cloud()
            .regtoken();
    public static final Endpoints SUBSCRIPTIONS_URL = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/users/ME/endpoints/SELF/subscriptions")
            .cloud()
            .regtoken();
    public static final Endpoints MESSAGINGSERVICE_URL = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/users/ME/endpoints/%s/presenceDocs/messagingService")
            .cloud()
            .regtoken();
    public static final Endpoints POLL = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/users/ME/endpoints/SELF/subscriptions/%s/poll")
            .cloud()
            .regtoken();
    public static final Endpoints NEW_GUEST = new Endpoints("https://join.skype.com/api/v1/users/guests");
    public static final Endpoints LEAVE_GUEST = new Endpoints("https://join.skype.com/guests/leave?threadId=%s");
    public static final Endpoints ACTIVE = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/users/ME/endpoints/%s/active").cloud().regtoken();
    public static final Endpoints LOAD_CHATS = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/users/ME/conversations?startTime=%s&pageSize=%s&view=msnp24Equivalent&targetType=Passport|Skype|Lync|Thread|PSTN|Agent")
            .cloud()
            .regtoken();
    public static final Endpoints LOAD_MESSAGES = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/users/ME/conversations/%s/messages?startTime=0&pageSize=%s&view=msnp24Equivalent|supportsMessageProperties&targetType=Passport|Skype|Lync|Thread")
            .cloud()
            .regtoken();
    public static final Endpoints OBJECTS = new Endpoints("https://api.asm.skype.com/v1/objects").defaultHeader(
            "Authorization", AUTHORIZATION);
    public static final Endpoints UPLOAD_IMAGE = new Endpoints(
            "https://api.asm.skype.com/v1/objects/%s/content/%s").defaultHeader("Authorization", AUTHORIZATION);
    public static final Endpoints IMG_STATUS = new Endpoints(
            "https://api.asm.skype.com/v1/objects/%s/views/%s/status").defaultHeader("Cookie", COOKIE);
    public static final Endpoints FETCH_IMAGE = new Endpoints(
            "https://api.asm.skype.com/v1/objects/%s/views/%s").defaultHeader("Authorization", AUTHORIZATION);
    public static final Endpoints VISIBILITY = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/users/ME/presenceDocs/messagingService")
            .cloud()
            .regtoken();
    public static final Endpoints SEARCH_SKYPE_DIRECTORY = new Endpoints(
            "https://api.skype.com/search/users/any?keyWord=%s&contactTypes[]=skype").skypetoken();
    public static final Endpoints GET_ALL_CONTACTS = new Endpoints(
            "https://contacts.skype.com/contacts/v2/users/%s/contacts?delta&$filter=type%%20eq%%20%%27skype%%27%%20or%%20type%%20eq%%20%%27msn%%27%%20or%%20type%%20eq%%20%%27pstn%%27%%20or%%20type%%20eq%%20%%27agent%%27%%20or%%20type%%20eq%%20%%27lync%%27&reason=%s")
            .skypetoken();
    public static final Endpoints GET_CONTACT_BY_ID = new Endpoints(
            "https://contacts.skype.com/contacts/v2/users/%s/contacts?$filter=id%%20eq%%20%%27%s%%27&reason=default").skypetoken();
    public static final Endpoints BLOCK_CONTACT = new Endpoints(
            "https://api.skype.com/users/self/contacts/%s/block").skypetoken();
    public static final Endpoints UNBLOCK_CONTACT = new Endpoints(
            "https://api.skype.com/users/self/contacts/%s/unblock").skypetoken();
	public static final Endpoints AUTHORIZE_CONTACT_SELF = new Endpoints(
            "https://%sclient-s.gateway.messenger.live.com/v1/users/ME/contacts/%s").cloud().regtoken();
    public static final Endpoints UNAUTHORIZE_CONTACT = new Endpoints(
			"https://contacts.skype.com/contacts/v2/users/%s/contacts/%s").skypetoken();
    public static final Endpoints UNAUTHORIZE_CONTACT_SELF = new Endpoints(
			"https://%sclient-s.gateway.messenger.live.com/v1/users/ME/contacts/%s").cloud().regtoken();

    public static final Endpoints SEND_CONTACT_REQUEST = new Endpoints(
            "https://contacts.skype.com/contacts/v2/users/%s/contacts").skypetoken();
    @Deprecated
    public static final Endpoints CONTACT_INFO = new Endpoints(
            "https://api.skype.com/users/self/contacts/profiles").skypetoken();
    public static final Endpoints PROFILE_INFO = new Endpoints("https://api.skype.com/users/batch/profiles").skypetoken();
    public static final Endpoints RECONNECT_WEBSOCKET = new Endpoints(
            "https://go.trouter.io/v2/h?ccid=%s&dom=web.skype.com");
    public static final Endpoints ELIGIBILITY_CHECK = new Endpoints("https://web.skype.com/api/v2/eligibility-check").skypetoken();

    public static final Endpoints AGENT_INFO = new Endpoints("https://api.aps.skype.com/v1/agents?agentId=%s").skypetoken();

    // todo implement
    // what other scopes are there?
    public static final Endpoints LANGUAGES_GET = new Endpoints("https://dev.microsofttranslator.com/api/languages?scope=text").skypetoken();

    public static final Endpoints NEW_KEY = new Endpoints("https://kes.skype.com/v2/swx/newkey").skypetoken();
    public static final Endpoints PETOKEN = new Endpoints("https://static.asm.skype.com/pes/v1/petoken").defaultHeader("Authorization", AUTHORIZATION);
    public static final Endpoints PROFILE = new Endpoints("https://api.skype.com/users/self/profile").skypetoken();

    private boolean requiresCloud;
    private boolean requiresRegToken;
    private boolean requiresSkypeToken;

    public Map<String, Provider<String>> providers() {
        return Collections.unmodifiableMap(providers);
    }

    public Map<String, Provider<String>> providers = new HashMap<>();

    private String url;

    public String url() {
        return this.url;
    }

    @Override public String toString() {
        final StringBuilder sb = new StringBuilder("Endpoints{");
        sb.append("requiresCloud=").append(requiresCloud);
        sb.append(", requiresRegToken=").append(requiresRegToken);
        sb.append(", requiresSkypeToken=").append(requiresSkypeToken);
        sb.append(", url='").append(url).append('\'');
        sb.append('}');
        return sb.toString();
    }

    private Endpoints(String url) {
        this.url = url;
    }

    public static EndpointConnection<HttpURLConnection> custom(String url, SkypeImpl skype, String... args) {
        if (skype.isShutdownRequested()) {
            throw new IllegalStateException("API is shut down");
        }
        return new EndpointConnection(new Endpoints(url), skype, args).as(HttpURLConnection.class);
    }

    public EndpointConnection<HttpURLConnection> open(SkypeImpl skype, Object... args) {
        if (skype.isShutdownRequested()) {
            throw new IllegalStateException("API is shut down");
        }
        return new EndpointConnection(this, skype, args).as(HttpURLConnection.class);
    }

    private Endpoints cloud() {
        this.requiresCloud = true;
        return this;
    }

    public boolean isLocationRequired() {
        return requiresCloud;
    }

    public boolean isRegTokenRequired() {
        return requiresRegToken;
    }

    public boolean isSkypeTokenRequired() {
        return requiresSkypeToken;
    }

    private Endpoints regtoken() {
        this.requiresRegToken = true;
        return this;
    }

    private Endpoints skypetoken() {
        this.requiresSkypeToken = true;
        return this;
    }

    private Endpoints defaultHeader(String key, Provider<String> val) {
        this.providers.put(key, val);
        return this;
    }

    public interface Provider<T> {
        T provide(SkypeImpl skype);
    }

    public interface Converter<T> {
        T convert(HttpURLConnection connection) throws IOException;
    }

    public interface UncheckedFunction<R> extends Function<HttpURLConnection, R> {
        default R apply(HttpURLConnection httpURLConnection) {
            try {
                return apply0(httpURLConnection);
            } catch (Throwable t) {
                Utils.sneakyThrow(t);
            }
            return null;
        }

        R apply0(HttpURLConnection httpURLConnection) throws Throwable;
    }
}
