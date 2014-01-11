package services.bindings;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class WebServer {
	private static final int POOL_MULTIPLE = 4;
	private static final int PORT = 8084;

	private ServerSocketChannel serverSocketChannel = null;
	private ExecutorService executorService;

	public static void main(String[] args) throws IOException {
		new WebServer().run();
	}

	public WebServer() throws IOException {
		executorService = Executors.newFixedThreadPool(
				Runtime.getRuntime().availableProcessors() * POOL_MULTIPLE);
		serverSocketChannel = ServerSocketChannel.open();
		serverSocketChannel.socket().setReuseAddress(true);
		serverSocketChannel.socket().bind(new InetSocketAddress(PORT));
	}

	public void run() {
		while (true)
			try {
				SocketChannel socketChannel = serverSocketChannel.accept();
				if (socketChannel != null)
					executorService.execute(new HttpHandler(socketChannel));
			}
			catch (IOException e) {
				e.printStackTrace();
			}
	}

	static private class HttpHandler implements Runnable {
		private static final Charset CHARSET = Charset.forName("UTF-8");

		private SocketChannel socketChannel;

		public HttpHandler(SocketChannel socketChannel) {
			this.socketChannel = socketChannel;
		}

		@Override
		public void run() {
			try {
//				Socket socket = socketChannel.socket();
//				System.out.println(socket.getInetAddress() + ":" + socket.getPort());

				StringBuilder stringBuilder = new StringBuilder();
				ByteBuffer buffer = ByteBuffer.allocate(32768);

				while (socketChannel.read(buffer) > 0) {
					buffer.flip();
					stringBuilder.append(
							CHARSET.newDecoder().decode(buffer).toString());
					buffer.clear();
					break; // TODO: maybe check the HTTP header for
					       //       Content-Length attribute and end loop when
					       //       all content has been read or a timeout has
					       //       expired
				}

				String answer =
						"HTTP/1.1 200 OK\r\n" +
						"Content-Type: text/html\r\n\r\n" +
						"" +
						"<h1>Incoming HTTP Request</h1>" +
						"<pre>" + stringBuilder.toString() + "</pre>";

				buffer = ByteBuffer.wrap(answer.getBytes(CHARSET));
				while(buffer.hasRemaining())
					socketChannel.write(buffer);
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
}
