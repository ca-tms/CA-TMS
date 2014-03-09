package services.bindings;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.cert.CertificateFactory;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonReader;

import support.Service;
import util.ValidationResult;
import buisness.TrustComputation;
import data.Configuration;
import data.Model;
import data.TrustCertificate;
import data.TrustView;

public class WebServer {
	private Thread thread;
	private ServerSocketChannel serverSocketChannel;
	private ExecutorService executorService;

	public WebServer() {
		executorService = Executors.newCachedThreadPool();
	}

	public void start() throws IOException {
		if (thread == null) {
			final int port;
			final int timeoutMillis;
			try (Configuration config = Model.openConfiguration()) {
				port = config.get("server-port", Integer.class);
				timeoutMillis = config.get("server-request-timeout-millis", Integer.class);
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

	public void stop() {
		if (thread != null) {
			thread.interrupt();
			thread = null;
		}
	}

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
				try {
					if (socketChannel.socket().getInetAddress().isLoopbackAddress()) {
						// parse incoming data as JSON
						// but cancel if a specified timeout expires
						Future<JsonObject> objectFuture = executorService.submit(
								new JsonObjectReader(reader));
						JsonObject object = objectFuture.get(
								timeoutMillis, TimeUnit.MILLISECONDS);

						// get certificate chain
						JsonArray chain = object.getJsonArray("certChain");

						CertificateFactory factory = CertificateFactory.getInstance("X.509");
						List<TrustCertificate> path = new ArrayList<>(chain.size());

						for (JsonArray jsonCert : chain.getValuesAs(JsonArray.class)) {
							int i = 0;
							byte[] certBytes = new byte[jsonCert.size()];
							for (JsonNumber jsonByte : jsonCert.getValuesAs(JsonNumber.class))
								certBytes[i++] = (byte) jsonByte.intValue();

							path.add(new TrustCertificate(
									factory.generateCertificate(
											new ByteArrayInputStream(certBytes))));
						}

						// get security level
						String securityLevel = Configuration.SECURITY_LEVEL_HIGH;
						switch (object.getString("secLevel")) {
						case "high":
							securityLevel = Configuration.SECURITY_LEVEL_HIGH;
							break;
						case "medium":
							securityLevel = Configuration.SECURITY_LEVEL_MEDIUM;
							break;
						case "low":
							securityLevel = Configuration.SECURITY_LEVEL_LOW;
							break;
						}

						// get validation result
						boolean validCertificateChain = false;
						switch (object.getString("validationResult")) {
						case "valid":
							validCertificateChain = true;
							break;
						}

						// perform trust validation
						String result = ValidationResult.UNTRUSTED.toString();
						if (validCertificateChain) {
							int attempts = 0;
							while (true) {
								try (TrustView trustView = Model.openTrustView();
								     Configuration config = Model.openConfiguration()) {
									result = new TrustComputation(config, trustView).validate(
											path, config.get(securityLevel, Double.class),
											Service.getValidationService(executorService)).toString();
								}
								catch (Exception e) {
									if (attempts == 0)
										e.printStackTrace();

									if (++attempts >= 60)
										throw e;

									System.err.println("TrustView update failed. This may happen due to concurrent access. Retrying ...");
									Thread.sleep(500);
									continue;
								}
								break;
							}
						}

						writer.write(
								"HTTP/1.1 200 OK\r\n" +
								"Content-Type: text/plain;charset=utf-8\r\n" +
								"Date: " + dateFormat.format(new Date()) + "\r\n" +
								"Connection: close\r\n" +
								"\r\n" +
								result);
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
