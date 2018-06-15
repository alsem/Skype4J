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

package com.samczsun.skype4j.internal.threads;

import com.eclipsesource.json.JsonObject;
import com.samczsun.skype4j.exceptions.ConnectionException;
import com.samczsun.skype4j.exceptions.handler.ErrorSource;
import com.samczsun.skype4j.internal.Endpoints;
import com.samczsun.skype4j.internal.SkypeImpl;
import com.samczsun.skype4j.internal.Utils;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class ActiveThread extends Thread {
    private static final Map<String, AtomicInteger> ID = new ConcurrentHashMap<>();

    private SkypeImpl skype;
    private String endpoint;

    private AtomicBoolean stop = new AtomicBoolean(false);

    public ActiveThread(SkypeImpl skype, String endpoint) {
        super(String.format("Skype4J-Active-%s-%s", skype.getUsername(), ID.computeIfAbsent(skype.getUsername(), str -> new AtomicInteger()).getAndIncrement()));
        this.skype = skype;
        this.endpoint = endpoint;
    }

    public void run() {
        while (skype.isLoggedIn() && !stop.get()) {
            if (!skype.isAuthenticated() || !skype.isRegistrationTokenValid()) {
                return;
            }
            try {
                Endpoints.ACTIVE.open(skype, endpoint)
                        .header("BehaviorOverride", "redirectAs404")
                        .expect(201, "While submitting active in " + this.getName())
                        .on(404, (connection) -> Endpoints
                                .custom(Endpoints.ENDPOINTS_URL.url() + "/" + endpoint, skype)
                                .expect(200, "While refreshing endpoint")
                                .header("Authentication", "skypetoken=" + skype.getSkypeToken())
                                .header("LockAndKey", Utils.generateChallengeHeader())
                                .put(new JsonObject().add("endpointFeatures", "Agent")))
                        .post(new JsonObject().add("timeout", 12));
            } catch (ConnectionException e) {
                skype.handleError(ErrorSource.SESSION_ACTIVE, e, false);
            }
            if (stop.get()) {
                return;
            }
            try {
                Thread.sleep(Duration.ofSeconds(12).toMillis());
            } catch (InterruptedException ignored) {
            }
        }
    }

    public void kill() {
        stop.set(true);
        System.out.println("ActiveCheckThread is shutting down");
        this.interrupt();
    }
}
