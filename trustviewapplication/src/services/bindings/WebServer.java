/*
 * This file is part of the CA Trust Management System (CA-TMS)
 *
 * Copyright 2015 by CA-TMS Team.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package services.bindings;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import services.ValidationInformation;
import services.ValidationRequest;
import services.Validator;

import data.Configuration;
import data.Model;

/**
 * Implements a web server binding. The web server can be queried by using a
 * HTTP interface from a local client.
 *
 * @author Pascal Weisenburger
 * @author Jannik Vieten
 * @author Haixin Cai
 */
public class WebServer {
	private Thread thread;
	private ServerSocketChannel serverSocketChannel;
	private ExecutorService executorService;

	/**
	 * Creates a new <code>WebServer</code> instance
	 */
	public WebServer() {
		executorService = Executors.newCachedThreadPool();
	}

	/**
	 * Starts the web server listening on the configured port
	 * @throws IOException
	 */
	public void start() throws IOException {
		if (thread == null) {
			final int port;
			final int timeoutMillis;
			try (Configuration config = Model.openConfiguration()) {
				port = config.get(Configuration.SERVER_PORT, Integer.class);
				timeoutMillis = config.get(Configuration.SERVER_REQUEST_TIMEOUT_MILLIS, Integer.class);
			}
			catch (Exception e) {
				// this should never happen, since we only read configuration values
				e.printStackTrace();
				return;
			}

			serverSocketChannel = ServerSocketChannel.open();
			serverSocketChannel.socket().setReuseAddress(true);
			serverSocketChannel.socket().bind(new InetSocketAddress(port));

			thread = new Thread() {
				@Override
				public void run() {
					while(!Thread.currentThread().isInterrupted()) {
						try {
							SocketChannel socketChannel = serverSocketChannel.accept();
							if (socketChannel != null)
								executorService.execute(new CommunicationHandler(
										socketChannel, executorService, timeoutMillis));
						}
						catch(ClosedByInterruptException e) {
							// this happens regularly on server shutdown
							try {
								serverSocketChannel.close();
							}
							catch (IOException e1) {
								e1.printStackTrace();
							}
						}
						catch (IOException e) {
							e.printStackTrace();
						}
					}
				}
			};
			thread.start();
		}
	}

	/**
	 * Stops a running the web server from listening to incoming HTTP queries
	 * @throws IOException
	 */
	public void stop() {
		if (thread != null) {
			thread.interrupt();
			thread = null;
		}
	}

	/**
	 * Implements the parsing of HTTP requests, the creation of HTTP responses
	 * and the delegation of queries to the {@link Validator}
	 */
	static private class CommunicationHandler implements Runnable {
		private final SocketChannel socketChannel;
		private final ExecutorService executorService;
		private final int timeoutMillis;

		private final static SimpleDateFormat dateFormat;

		static {
			dateFormat = new SimpleDateFormat("EEE, MMM d yyyy HH:mm:ss z");
			dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
		}

		public CommunicationHandler(SocketChannel socketChannel,
				ExecutorService executorService, int timeoutMillis) {
			this.socketChannel = socketChannel;
			this.executorService = executorService;
			this.timeoutMillis = timeoutMillis;
		}

		@Override
		public void run() {
			try (Reader reader = Channels.newReader(socketChannel, "UTF-8");
			     Writer writer = Channels.newWriter(socketChannel, "UTF-8")) {

				Future<JsonObject> objectFuture = null;
				try {
					if (socketChannel.socket().getInetAddress().isLoopbackAddress()) {
						// parse incoming data as JSON
						// but cancel if a specified timeout expires
						objectFuture = executorService.submit(
								new JsonObjectReader(reader));
						JsonObject object = objectFuture.get(
								timeoutMillis, TimeUnit.MILLISECONDS);

						// decode JSON object
						ValidationRequest request = JsonRequestDecoder.decode(object);

						// perform trust validation
						ValidationInformation result = Validator.validate(request);

						// create answer JSON string
						StringBuilder jsonResult = new StringBuilder();

						jsonResult.append("{\n  \"result\": ");
						switch (result.getValidationResult()) {
						case TRUSTED:
							jsonResult.append("\"trusted\"");
							break;
						case UNTRUSTED:
							jsonResult.append("\"untrusted\"");
							break;
						case UNKNOWN:
							jsonResult.append("\"unknown\"");
							break;
						}

						jsonResult.append(",\n  \"resultSpec\": ");
						switch (result.getValidationResultSpec()) {
						case VALIDATED:
							jsonResult.append("\"validated\"");
							break;
						case VALIDATED_FIRST_SEEN:
							jsonResult.append("\"validated-first-seen\"");
							break;
						case VALIDATED_EXISTING_EXPIRED_SAME_CA:
							jsonResult.append("\"validated-existing-expired-same-ca\"");
							break;
						case VALIDATED_EXISTING_EXPIRED_SAME_CA_KEY:
							jsonResult.append("\"validated-existing-expired-same-ca-key\"");
							break;
						case VALIDATED_EXISTING_VALID_SAME_CA:
							jsonResult.append("\"validated-existing-valid-same-ca\"");
							break;
						case VALIDATED_EXISTING_VALID_SAME_KEY:
							jsonResult.append("\"validated-existing-valid-same-key\"");
							break;
						case VALIDATED_EXISTING:
							jsonResult.append("\"validated-existing\"");
							break;
						case VALIDATED_ON_WATCHLIST:
							jsonResult.append("\"validated-on-watchlist\"");
							break;
						case VALIDATED_REVOKED:
							jsonResult.append("\"validated-revoked\"");
							break;
						case RECOMMENDED:
							jsonResult.append("\"recommended\"");
							break;
						}

						jsonResult.append("\n}");

						writer.write(
								"HTTP/1.1 200 OK\r\n" +
								"Content-Type: application/json;charset=utf-8\r\n" +
								"Date: " + dateFormat.format(new Date()) + "\r\n" +
								"Connection: close\r\n" +
								"\r\n" +
								jsonResult.toString());
					}
					else {
						System.err.println("403 Forbidden");
						System.err.println("Request not from loopback address");
						writer.write(
								"HTTP/1.1 403 Forbidden\r\n" +
								"Content-Type: text/plain;charset=utf-8\r\n" +
								"Date: " + dateFormat.format(new Date()) + "\r\n" +
								"Connection: close\r\n" +
								"\r\n" +
								"403 Forbidden\r\n" +
								"Request not from loopback address\r\n" +
								dateFormat.format(new Date()));
					}
				}
				catch (TimeoutException e) {
					if (objectFuture != null)
						objectFuture.cancel(true);

					System.err.println("408 Request Timeout");
					e.printStackTrace();
					writer.write(
							"HTTP/1.1 408 Request Timeout\r\n" +
							"Content-Type: text/plain;charset=utf-8\r\n" +
							"Date: " + dateFormat.format(new Date()) + "\r\n" +
							"Connection: close\r\n" +
							"\r\n" +
							"408 Request Timeout\r\n" +
							dateFormat.format(new Date()));
				}
				catch (Exception e) {
					if (objectFuture != null)
						objectFuture.cancel(true);

					System.err.println("500 Internal Server Error");
					e.printStackTrace();
					writer.write(
							"HTTP/1.1 500 Internal Server Error\r\n" +
							"Content-Type: text/plain;charset=utf-8\r\n" +
							"Date: " + dateFormat.format(new Date()) + "\r\n" +
							"Connection: close\r\n" +
							"\r\n" +
							"500 Internal Server Error\r\n" +
							dateFormat.format(new Date()));
				}
			}
			catch (IOException e) {
				e.printStackTrace();
			}

			try {
				socketChannel.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Reads a JSON object from a HTTP stream's content
	 */
	static private class JsonObjectReader implements Callable<JsonObject> {
		private final BufferedReader reader;

		public JsonObjectReader(Reader reader) {
			this.reader = reader instanceof BufferedReader
					? (BufferedReader) reader
					: new BufferedReader(reader);
		}

		@Override
		public JsonObject call() throws Exception {
			// skip lines of HTTP protocol
			while (!reader.readLine().isEmpty());

			// read JSON object
			JsonReader jsonReader = Json.createReader(reader);
			return jsonReader.readObject();
		}

	}
}
