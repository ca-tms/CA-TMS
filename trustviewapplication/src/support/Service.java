package support;

import java.security.cert.Certificate;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import data.TrustCertificate;

import sslcheck.core.NotaryManager;
import sslcheck.core.TLSConnectionInfo;
import util.ValidationResult;

/**
 * Provides central access point for external services
 */
public final class Service {
	private Service() { }

	/**
	 * @return a {@link ValidationService} instance that can be used to query
	 * external validation services implemented as notaries
	 * @param host the host which validation is requested for
	 */
	public static ValidationService getValidationService(final String host) {
		return new ValidationService() {
			@Override
			public ValidationResult query(final TrustCertificate certificate) {
				try {
					
					NotaryManager nm = new NotaryManager();
				
					// Install the all-trusting trust manager
					final SSLContext sslContext = SSLContext.getInstance("TLS");
					sslContext.init(null,
							new TrustManager[] { nm.getTrustManager() 
							},
							new java.security.SecureRandom());

					// Install as default TLS Socket Factory, so it is also used by
					// notaries!
					// https://stackoverflow.com/questions/6047996/ignore-self-signed-ssl-cert-using-jersey-client
					HttpsURLConnection.setDefaultSSLSocketFactory(sslContext
							.getSocketFactory());
					
					TLSConnectionInfo info = new TLSConnectionInfo(
							host,443, new Certificate[] { certificate.getCertificate() });
					info.validateCertificates(nm);
					return info.isTrusted() ?
							ValidationResult.TRUSTED : ValidationResult.UNTRUSTED;
				}
				catch (Exception e) {
					e.printStackTrace();
					return ValidationResult.UNKNOWN;
				}
			}
		};
	}

	/**
	 * @return a {@link ValidationService} instance that can be used to query
	 * external validation services implemented as notaries
	 * @param host the host which validation is requested for
	 * @param timeoutMillis the number of milliseconds which the query should be
	 * cancelled after
	 * @throws CancellationException if the query was cancelled due to timeout
	 */
	public static ValidationService getValidationService(final String host,
			final long timeoutMillis) {
		final ValidationService validationService = getValidationService(host);
		final ExecutorService executorService = Executors.newSingleThreadExecutor();

		return new ValidationService() {
			@Override
			public ValidationResult query(final TrustCertificate certificate) {
				Future<ValidationResult> resultFuture = executorService.submit(
						new Callable<ValidationResult>() {
							@Override
							public ValidationResult call() throws Exception {
								return validationService.query(certificate);
							}
						});

				try {
					return resultFuture.get(timeoutMillis, TimeUnit.MILLISECONDS);
				}
				catch (TimeoutException e) {
					resultFuture.cancel(true);
					throw new CancellationException("Validation service timed out");
				}
				catch (Exception e) {
					e.printStackTrace();
					resultFuture.cancel(true);
					return ValidationResult.UNKNOWN;
				}
			}
		};
	}
}
