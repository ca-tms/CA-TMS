package util;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
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
	 * @return the user configuration directory,
	 * this is where an application can store user-specific preferences
	 */
	public static String getConfigDirectory() {
		String OS = System.getProperty("os.name").toUpperCase();
		if (OS.contains("WIN"))
			return System.getenv("APPDATA");
		else if (OS.contains("MAC"))
			return System.getProperty("user.home") + "/Library/Preferences";
		else if (OS.contains("NUX")) {
			String dir = System.getenv("XDG_CONFIG_HOME");
			if (dir != null && !dir.isEmpty())
				return dir;
			return System.getProperty("user.home") + "/.config";
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

	/**
	 * Attempts to clear the {@link CertificateFactory} cache
	 */
	public static void tryClearCertificateFactoryCache() {
		CertificateFactory factory;

		try {
			factory = CertificateFactory.getInstance("X.509");
		}
		catch (Exception e) {
			return;
		}

		// passing null will throw an exception
		// but will also clear the cache on common implementations
		// although this is not a documented API feature

		try {
			factory.generateCertificate(null);
		}
		catch (Exception e) { }

		try {
			factory.generateCRL(null);
		}
		catch (Exception e) { }

		System.gc();
	}
}
