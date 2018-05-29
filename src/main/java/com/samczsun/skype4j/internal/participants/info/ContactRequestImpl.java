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

package com.samczsun.skype4j.internal.participants.info;

import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.client.FullClient;
import com.samczsun.skype4j.participants.info.Contact;
import org.apache.commons.lang3.StringUtils;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

public class ContactRequestImpl implements Contact.ContactRequest {

    private final Date time;
    private final String sender;
    private final String message;
    private final FullClient skype;

    public ContactRequestImpl(String time, String sender, String message, FullClient skype) throws ParseException {
        this.time = Date.from(Instant.parse(time));
        this.sender = sender;
        this.message = message;
        this.skype = skype;
    }

    @Override
    public Date getTime() {
        return new Date(this.time.getTime());
    }

    @Override
    public Contact getSender() throws ConnectionException {
        return skype.getOrLoadContact(this.sender);
    }

    @Override
    public String getMessage() {
        return this.message;
    }

    @Override
    public void accept() throws ConnectionException {
        Endpoints.ACCEPT_CONTACT_REQUEST
                .open(skype, skype.getUsername(), sender)
                .expect(200, "While accepting contact request")
                .put();
        getSender().authorize();
    }

    @Override
    public void decline() throws ConnectionException {
        Endpoints.DECLINE_CONTACT_REQUEST
                .open(skype, skype.getUsername(), sender)
                .expect(200, "While declining contact request")
                .put();
        Endpoints.UNAUTHORIZE_CONTACT_SELF.open(skype,StringUtils.prependIfMissing(sender, "8:"))
                .expect(200, "While unauthorizing contact").delete();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ContactRequestImpl that = (ContactRequestImpl) o;

        if (time != null ? !time.equals(that.time) : that.time != null) return false;
        if (sender != null ? !sender.equals(that.sender) : that.sender != null) return false;
        return !(message != null ? !message.equals(that.message) : that.message != null);

    }

    @Override
    public int hashCode() {
        int result = time != null ? time.hashCode() : 0;
        result = 31 * result + (sender != null ? sender.hashCode() : 0);
        result = 31 * result + (message != null ? message.hashCode() : 0);
        return result;
    }
}
