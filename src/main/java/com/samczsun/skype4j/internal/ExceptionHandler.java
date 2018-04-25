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

import com.samczsun.skype4j.exceptions.ConnectionException;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.List;
import java.util.Map;

public class ExceptionHandler {
    private static final boolean DEBUG =
            AccessController.doPrivileged((PrivilegedAction<Boolean>) () ->
                    Boolean.getBoolean("com.samczsun.skype4j.debugExceptions"));

    public static ConnectionException generateException(String reason, HttpURLConnection connection) {
        try {
            if (DEBUG) {
                System.err.println("URL");
                System.err.println("\t" + connection.getURL());
//                printRequestHeaders(connection);
                printResponseHeaders(connection);
                printPostData(connection);
            }
            return new ConnectionException(reason, connection);
        } catch (IOException e) {
            throw new RuntimeException(String.format("IOException while constructing exception (%s, %s)", reason, connection));
        } finally {
            connection.disconnect();
        }
    }

    private static void printPostData(HttpURLConnection connection) {

        System.err.println("Post data");
        try {
            System.err.println("\t" + connection.getOutputStream());
        } catch (IOException ignored) {

        }
    }

    private static void printResponseHeaders(HttpURLConnection connection) {
        System.err.println("Response headers");
        for (Map.Entry<String, List<String>> header : connection.getHeaderFields().entrySet()) {
            System.err.println(String.format("\t%s - %s", header.getKey(), header.getValue()));
        }
    }

    private static void printRequestHeaders(HttpURLConnection connection) {
        for (String header : connection.getRequestProperties().keySet()) {
            if (header != null) {
                for (String value : connection.getRequestProperties().get(header)) {
                    System.out.println(header + ":" + value);
                }
            }
        }
    }

    public static ConnectionException generateException(String reason, IOException nested) {
        return new ConnectionException(reason, nested);
    }
}
