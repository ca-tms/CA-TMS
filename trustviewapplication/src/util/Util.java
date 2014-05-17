package util;

import java.io.IOException;
import java.net.ConnectException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Provides general utility functions
 */
public final class Util {
	private Util() { }

	/**
	 * @return the user data directory,
	 * this is where an application can store user-specific data
	 */
	public static String getDataDirectory() {
		String OS = System.getProperty("os.name").toUpperCase();
		if (OS.contains("WIN"))
			return System.getenv("APPDATA");
		else if (OS.contains("MAC"))
			return System.getProperty("user.home") + "/Library/Application Support";
		else if (OS.contains("NUX")) {
			String dir = System.getenv("XDG_DATA_HOME");
			if (dir != null && !dir.isEmpty())
				return dir;
			return System.getProperty("user.home") + "/.local/share";
		}
		return System.getProperty("user.dir");
	}

	/**
	 * Retrieves the certificate chain from the given host
	 * @return the certificate chain with the certificate for the host first
	 * followed by the certificates for any certificate authorities
	 * @param host
	 * @throws UnknownHostException
	 * @throws IOException
	 * not support TLS
	 */
	public static Certificate[] retrieveCertificateChain(String host)
			throws UnknownHostException, IOException {
		try {
			final SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(
				null,
				new TrustManager[] {
					new X509TrustManager() {
						@Override
						public java.security.cert.X509Certificate[] getAcceptedIssuers() {
							return null;
						}
						@Override
						public void checkClientTrusted(X509Certificate[] certs,
								String authType) { }
						@Override
						public void checkServerTrusted(X509Certificate[] certs,
								String authType) { }
					}
				},
				new java.security.SecureRandom());

			try (SSLSocket socket =
					(SSLSocket) sslContext.getSocketFactory().createSocket(host, 443)) {
				socket.startHandshake();
				return socket.getSession().getPeerCertificates();
			}
		}
		catch (NoSuchAlgorithmException | KeyManagementException e) {
			e.printStackTrace();
		}
		return new Certificate[] { };
	}
}
