package support.bootstrap;

import java.net.URL;
import java.security.cert.Certificate;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import services.logic.ValidationRequest;
import services.logic.Validator;
import util.CertificatePathValidity;
import util.Util;
import data.TrustCertificate;

import support.BootstrapService;

final public class URLBootstrapping {
	private URLBootstrapping() { }

	public static boolean bootstrap(Iterator urls, int maxSize,
			double securityLevel, BootstrapService.Observer observer)
	throws Exception {
		URL url = null;
		String host = null;
		double cur = 0, max = maxSize;

		Map<String, List<TrustCertificate>> hostCertificates = new HashMap<>();
		Map<String, String> failedHosts = new HashMap<>();
		while (urls.hasNext())
			try {
				url = urls.next();
				host = url.getHost();

				cur++;
				if (observer != null)
					try {
						if (!observer.update(cur / max, url.toString()))
							return false;
					}
					catch (Exception e) {
						e.printStackTrace();
					}
				
				//validation is only done for newly observed hosts 
				List<TrustCertificate> certificates = hostCertificates.get(host);
				if (certificates == null && !failedHosts.containsKey(host)) {
					
					System.out.println("Performing bootstrapping validation ...");
					System.out.println("  URL: " + url);
					System.out.println("  Host: " + host);
					
					Certificate[] path = Util.retrieveCertificateChain(host);

					certificates = new ArrayList<>(
							Collections.<TrustCertificate>nCopies(
									path.length, null));

					int i = path.length - 1;
					for (Certificate cert : path)
						certificates.set(i--, new TrustCertificate(cert));

					hostCertificates.put(host, certificates);
				

					ValidationRequest request = new ValidationRequest(
							url.toString(),
							certificates,
							CertificatePathValidity.VALID,
							securityLevel,
							false);
					
					Validator.validate(request);
				}
			}
			catch (Exception e) {
				failedHosts.put(host, e.toString());
				System.out.println("Bootstrapping validation failed");
				System.out.println("  URL: " + url);
				System.out.println("  Host: " + host);
				e.printStackTrace();
			}
		return true;
	}

	public static Iterator iterator(final ResultSet result,
			final int urlColumn) {
		return new Iterator() {
			private URL next = null;
			private boolean hasNext = true;

			@Override
			public boolean hasNext() throws Exception {
				if (next != null)
					return true;

				if (!hasNext)
					return false;

				if (result.next()) {
					next = new URL(result.getString(urlColumn));
					return true;
				}
				else {
					hasNext = false;
					return false;
				}
			}

			@Override
			public URL next() throws Exception {
				if (!hasNext())
					throw new NoSuchElementException();
				URL temp = next;
				next = null;
				return temp;
			}
		};
	}

	public static Iterator iterator(final Iterable<URL> iterable) {
		return iterator(iterable.iterator());
	}

	public static Iterator iterator(final java.util.Iterator<URL> iterator) {
		return new Iterator() {
			@Override
			public boolean hasNext() {
				return iterator.hasNext();
			}

			@Override
			public URL next() {
				return iterator.next();
			}
		};
	}

	public static interface Iterator {
		boolean hasNext() throws Exception;
		URL next() throws Exception;
	};
}
