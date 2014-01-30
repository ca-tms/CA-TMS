package services.bindings;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.nio.channels.Channels;
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

import buisness.TrustComputation;
import data.Model;
import data.TrustCertificate;
import data.TrustView;

public class WebServer {
	private static final int PORT = 8084;
	private static final int TIMEOUT_MILLIS = 5000;

	private final ServerSocketChannel serverSocketChannel;
	private final ExecutorService executorService;

	public static void main(String[] args) throws Exception {
		new WebServer().run();
	}

	public WebServer() throws IOException {
		executorService = Executors.newCachedThreadPool();

		serverSocketChannel = ServerSocketChannel.open();
		serverSocketChannel.socket().setReuseAddress(true);
		serverSocketChannel.socket().bind(new InetSocketAddress(PORT));
	}

	public void run() {
		while (true)
			try {
				SocketChannel socketChannel = serverSocketChannel.accept();
				if (socketChannel != null)
					executorService.execute(new CommunicationHandler(
							socketChannel, executorService));
			}
			catch (IOException e) {
				e.printStackTrace();
			}
	}

	static private class CommunicationHandler implements Runnable {
		private final SocketChannel socketChannel;
		private final ExecutorService executorService;

		private final static SimpleDateFormat dateFormat;

		static {
			dateFormat = new SimpleDateFormat("EEE, MMM d yyyy HH:mm:ss z");
			dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
		}

		public CommunicationHandler(SocketChannel socketChannel,
				ExecutorService executorService) {
			this.socketChannel = socketChannel;
			this.executorService = executorService;
		}

		@Override
		public void run() {
			try (Reader reader = Channels.newReader(socketChannel, "UTF-8");
			     Writer writer = Channels.newWriter(socketChannel, "UTF-8")) {
				try {
					if (socketChannel.socket().getInetAddress().isLoopbackAddress()) {
						Future<JsonObject> objectFuture = executorService.submit(
								new JsonObjectReader(reader));

						JsonObject object = objectFuture.get(
								TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
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

						String str = "(unknown)";

						int attempts = 0;
						while (true) {
							try (TrustView trustView = Model.openTrustView()) {
								str = new TrustComputation(trustView).validate(
										path, 0.8,
										Service.getValidationService(executorService)).toString();
							}
							catch (Exception e) {
								if (attempts == 0)
									e.printStackTrace();

								if (++attempts >= 60)
									throw e;

								System.err.println("TrustView update failed. Retrying ...");
								Thread.sleep(500);
								continue;
							}
							break;
						}

						writer.write(
								"HTTP/1.1 200 OK\r\n" +
								"Content-Type: text/plain;charset=utf-8\r\n" +
								"Date: " + dateFormat.format(new Date()) + "\r\n" +
								"Connection: close\r\n" +
								"\r\n" +
								str);
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
