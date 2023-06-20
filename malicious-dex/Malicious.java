import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

public class Malicious {
    public void main(String host, int port) {
        try {
            Socket socket = new Socket(host, port);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            out.write("Hello, DEX!".getBytes());
            out.flush();
            byte[] buffer = new byte[1024];
            int length = in.read(buffer);
            System.out.println(new String(buffer, 0, length));
            socket.close();
        } catch (UnknownHostException e) {
            System.out.println("UnknownHostException");
        } catch (IOException e) {
            System.out.println("IOException");
        }
    }
}

