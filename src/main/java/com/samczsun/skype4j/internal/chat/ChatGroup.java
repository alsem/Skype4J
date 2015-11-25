/*
 * Copyright 2015 Sam Sun <me@samczsun.com>
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

package com.samczsun.skype4j.internal.chat;

import com.eclipsesource.json.JsonArray;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import com.samczsun.skype4j.chat.GroupChat;
import com.samczsun.skype4j.events.chat.user.action.OptionUpdateEvent;
import com.samczsun.skype4j.exceptions.ChatNotFoundException;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.NotParticipatingException;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.ExceptionHandler;
import com.samczsun.skype4j.internal.client.GuestClient;
import com.samczsun.skype4j.internal.SkypeImpl;
import com.samczsun.skype4j.internal.UserImpl;
import com.samczsun.skype4j.user.Contact;
import com.samczsun.skype4j.user.User;
import com.samczsun.skype4j.user.User.Role;

import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ChatGroup extends ChatImpl implements GroupChat {
    private String topic;
    private String pictureUrl;
    private Set<OptionUpdateEvent.Option> enabledOptions;

    protected ChatGroup(SkypeImpl skype, String identity) throws ConnectionException, ChatNotFoundException {
        super(skype, identity);
    }

    protected void load() throws ConnectionException, ChatNotFoundException {
        if (isLoaded()) {
            return;
        }
        enabledOptions = new HashSet<>();
        boolean thrown = false;
        try {
            isLoading.set(true);
            Map<String, User> newUsers = new HashMap<>();
            HttpURLConnection con = Endpoints.CHAT_INFO_URL.open(getClient(), getIdentity()).get();

            if (con.getResponseCode() == 404) {
                throw new ChatNotFoundException();
            }
            if (con.getResponseCode() != 200) {
                throw ExceptionHandler.generateException("While loading users", con);
            }
            JsonObject object = JsonObject.readFrom(new InputStreamReader(con.getInputStream(), "UTF-8"));
            JsonObject props = object.get("properties").asObject();
            for (OptionUpdateEvent.Option option : OptionUpdateEvent.Option.values()) {
                if (props.get(option.getId()) != null && props.get(option.getId()).asString().equals("true")) {
                    this.enabledOptions.add(option);
                }
            }
            if (props.get("topic") != null) {
                this.topic = props.get("topic").asString();
            } else {
                this.topic = "";
            }
            JsonArray members = object.get("members").asArray();
            for (JsonValue element : members) {
                String username = element.asObject().get("id").asString().substring(2);
                String role = element.asObject().get("role").asString();
                UserImpl user = (UserImpl) users.get(username.toLowerCase());
                if (user == null) {
                    user = new UserImpl(username, this, getClient());
                }
                newUsers.put(username.toLowerCase(), user);
                if (role.equalsIgnoreCase("admin")) {
                    user.updateRole(Role.ADMIN);
                } else {
                    user.updateRole(Role.USER);
                }
            }

            if (newUsers.get(getClient().getUsername().toLowerCase()) == null && !(getClient() instanceof GuestClient)) {
                throw new NotParticipatingException();
            }

            this.users.clear();
            this.users.putAll(newUsers);
        } catch (IOException e) {
            thrown = true;
            throw ExceptionHandler.generateException("While loading", e);
        } finally {
            if (!thrown) {
                hasLoaded.set(true);
            }
            isLoading.set(false);
        }
    }

    public void addUser(String username) throws ConnectionException {
        if (!users.containsKey(username.toLowerCase())) {
            User user = new UserImpl(username, this, getClient());
            users.put(username.toLowerCase(), user);
        } else if (!username.equalsIgnoreCase(getClient().getUsername())) { //Skype...
            throw new IllegalArgumentException(username + " joined the chat even though he was already in it?");
        }
    }

    public void removeUser(String username) {
        users.remove(username.toLowerCase());
    }

    public void kick(String username) throws ConnectionException {
        checkLoaded();
        try {
            HttpURLConnection con = Endpoints.MODIFY_MEMBER_URL.open(getClient(), getIdentity(), username).delete();
            if (con.getResponseCode() != 200) {
                throw ExceptionHandler.generateException("While kicking user", con);
            }
        } catch (IOException e) {
            throw ExceptionHandler.generateException("While kicking user", e);
        }
    }

    public void leave() throws ConnectionException {
        kick(getClient().getUsername());
    }

    @Override
    public String getJoinUrl() throws ConnectionException {
        checkLoaded();
        if (isOptionEnabled(OptionUpdateEvent.Option.JOINING_ENABLED)) {
            try {
                JsonObject data = new JsonObject();
                data.add("baseDomain", "https://join.skype.com/launch/");
                data.add("threadId", this.getIdentity());
                HttpURLConnection connection = Endpoints.GET_JOIN_URL.open(getClient()).post(data);
                if (connection.getResponseCode() != 200) {
                    throw ExceptionHandler.generateException("While getting join URL", connection);
                }
                JsonObject object = JsonObject.readFrom(new InputStreamReader(connection.getInputStream(), "UTF-8"));
                return object.get("JoinUrl").asString();
            } catch (IOException e) {
                throw ExceptionHandler.generateException("While getting join URL", e);
            }
        } else {
            throw new IllegalStateException("Joining is not enabled");
        }
    }

    @Override
    public String getTopic() {
        checkLoaded();
        return this.topic;
    }

    public void setTopic(String topic) throws ConnectionException {
        checkLoaded();
        putOption("topic", JsonValue.valueOf(topic));
    }

    @Override
    public boolean isOptionEnabled(OptionUpdateEvent.Option option) {
        checkLoaded();
        return this.enabledOptions.contains(option);
    }

    @Override
    public void setOptionEnabled(OptionUpdateEvent.Option option, boolean enabled) throws ConnectionException {
        checkLoaded();
        putOption(option.getId(), JsonValue.valueOf(enabled));
        updateOption(option, enabled);
    }

    @Override
    public void add(Contact contact) throws ConnectionException {
        checkLoaded();
        try {
            JsonObject obj = new JsonObject();
            obj.add("role", "User");
            HttpURLConnection con = Endpoints.ADD_MEMBER_URL.open(getClient(), getIdentity(), contact.getUsername()).put();
            if (con.getResponseCode() != 200) {
                throw ExceptionHandler.generateException("While adding user into group", con);
            }
        } catch (IOException e) {
            throw ExceptionHandler.generateException("While adding user into group", e);
        }
    }

    private void putOption(String option, JsonValue value) throws ConnectionException {
        try {
            JsonObject obj = new JsonObject();
            obj.add(option, value);
            HttpURLConnection con = Endpoints.MODIFY_PROPERTY_URL.open(getClient(), getIdentity(), option).put(obj);
            if (con.getResponseCode() != 200) {
                throw ExceptionHandler.generateException("While updating an option", con);
            }
        } catch (IOException e) {
            throw ExceptionHandler.generateException("While updating an option", e);
        }
    }

    public void updateTopic(String topic) {
        this.topic = topic;
    }

    public void updatePicture(String picture) {
        this.pictureUrl = picture;
    }

    public void updateOption(OptionUpdateEvent.Option option, boolean enabled) {
        if (enabled)
            enabledOptions.add(option);
        else
            enabledOptions.remove(option);
    }
}
