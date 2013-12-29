import java.net.*;
import java.nio.channels.*;
import java.util.concurrent.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
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
		// TODO 自动生成的方法存根
        new HttpLite().service();
	}

}




class HttpHandler implements Runnable {
    private SocketChannel socketChannel;
    public HttpHandler(SocketChannel socketChannel) {
        this.socketChannel = socketChannel;
    }
 
    @Override
    public void run() {
        handle(socketChannel);
    }
 
    private void handle(SocketChannel socketChannel) {
        try {
            Socket socket = socketChannel.socket();
            System.out
                    .println(socket.getInetAddress() + ":" + socket.getPort());
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            socketChannel.read(buffer);
            buffer.flip();
            String request = decode(buffer);
            StringBuffer sb = new StringBuffer("HTTP/1.1 0 OK\r\n");
            sb.append("Content-Type:text/html\r\n\r\n");
            socketChannel.write(encode(sb.toString()));
            FileInputStream in = null;
           
           
                in = new FileInputStream("hello.htm");
            FileChannel fileChannel = in.getChannel();
            fileChannel.transferTo(0, fileChannel.size(), socketChannel);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (socketChannel != null)
                    socketChannel.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
 
    private Charset charset = Charset.forName("GBK");
 
    private ByteBuffer encode(String string) {
        return ByteBuffer.allocate(string.length() * 2).get(
                string.getBytes(charset));
    }
 
    private String decode(ByteBuffer buffer) {
        byte[] source = new byte[buffer.position() + 1];
        buffer.put(source);
        return new String(source, charset);
    }
}

