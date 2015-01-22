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
package support.bootstrap;

import java.net.URL;
import java.security.cert.Certificate;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

import util.CertificatePathValidity;
import util.Util;
import data.TrustCertificate;

import services.ValidationRequest;
import services.ValidationRequestSpec;
import services.Validator;
import support.BootstrapService;

/**
 * @author Pascal Weisenburger
 */
final class URLBootstrapping {
	private URLBootstrapping() { }

	public static boolean bootstrap(Iterator urls, int maxSize,
			double securityLevel, BootstrapService.Observer observer)
	throws Exception {
		URL url = null;
		String host = null;
		double cur = 0, max = maxSize;

		Set<String> hosts = new HashSet<>();
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
				if (!hosts.contains(host)) {
					System.out.println("Performing bootstrapping validation ...");
					System.out.println("  URL: " + url);
					System.out.println("  Host: " + host);

					hosts.add(host);

					Certificate[] path = Util.retrieveCertificateChain(host);

					List<TrustCertificate> certificates = new ArrayList<>(
							Collections.<TrustCertificate>nCopies(
									path.length, null));

					int i = path.length - 1;
					for (Certificate cert : path)
						certificates.set(i--, new TrustCertificate(cert));

					ValidationRequest request = new ValidationRequest(
							url.toString(),
							certificates,
							CertificatePathValidity.VALID,
							securityLevel,
							ValidationRequestSpec.VALIDATE_WITH_SERVICES);

					Validator.validate(request);
				}
			}
			catch (Exception e) {
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
