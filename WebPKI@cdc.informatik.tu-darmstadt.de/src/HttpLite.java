import java.net.*;
import java.nio.channels.*;
import java.util.concurrent.*;
import java.io.*;

public class HttpLite {
    private int port =8084;
    private ServerSocketChannel serverSocketChannel = null;
    private ExecutorService executorService;
    private static final int POOL_MULTIPLE = 4;
 
    public HttpLite() throws IOException {
        executorService = Executors.newFixedThreadPool(Runtime.getRuntime()
                .availableProcessors() * POOL_MULTIPLE);
        serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.socket().setReuseAddress(true);
        serverSocketChannel.socket().bind(new InetSocketAddress(port));
    }
 
    public void service() {
        while (true) {
            SocketChannel socketChannel = null;
            try {
                socketChannel = serverSocketChannel.accept();
                executorService.execute(new HttpHandler(socketChannel));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

	public static void main(String[] args) throws IOException {
		// TODO �Զ����ɵķ������
        new HttpLite().service();
	}

}
