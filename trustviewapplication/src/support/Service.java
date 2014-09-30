package support;

import java.io.File;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import support.bootstrap.ChromiumBootstrapService;
import support.bootstrap.FirefoxBootstrapService;
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
							new TrustManager[] { nm.getTrustManager() },
							new java.security.SecureRandom());

					// Install as default TLS Socket Factory,
					// so it is also used by notaries
					// https://stackoverflow.com/questions/6047996/
					HttpsURLConnection.setDefaultSSLSocketFactory(sslContext
							.getSocketFactory());

					TLSConnectionInfo info = new TLSConnectionInfo(
							host, 443, new Certificate[] { certificate.getCertificate() });
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
	 * @return a {@link ValidationService} instance that can be used in
	 * conjunction with another {@link ValidationService} to force time
	 * constraints on querying that service
	 * @param timeoutMillis the number of milliseconds which the query should be
	 * cancelled after
	 * @param validationService the validation service that will be used to to
	 * query a validation result
	 * @throws CancellationException if the query was cancelled due to timeout
	 */
	public static ValidationService getValidationService(
			final long timeoutMillis, final ValidationService validationService) {
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

	/**
	 * @return a {@link ValidationService} instance that can be used in
	 * conjunction with another {@link ValidationService} to cache the query
	 * result of that service for further queries
	 * @param validationService the validation service that will be used to
	 * query a validation result
	 */
	public static ValidationService getValidationService(
			final ValidationService validationService) {
		final Map<TrustCertificate, ValidationResult> cache = new HashMap<>();
		return new ValidationService() {
			@Override
			public ValidationResult query(final TrustCertificate certificate) {
				ValidationResult result = cache.get(certificate);
				if (result != null)
					return result;

				result = validationService.query(certificate);
				cache.put(certificate, result);
				return result;
			}
		};
	}

	/**
	 * @return a {@link ValidationService} instance that can be used in
	 * conjunction with other {@link ValidationService}s to predefine
	 * certificates to be always trusted or untrusted.
	 * @param trustedCertificates a collection of certificates that will
	 * always validated to be trusted; can be <code>null</code>
	 * @param untrustedCertificates a collection of certificates that will
	 * always validated to be untrusted; can be <code>null</code>
	 * @param unknownCertificatesService another validation service that
	 * will be used to to query a validation result for certificates that
	 * are neither defined to be trusted nor defined to be untrusted;
	 * can be <code>null</code>, in which case certificates will be validated
	 * to be of unknown trust
	 */
	public static ValidationService getValidationService(
			final Collection<TrustCertificate> trustedCertificates,
			final Collection<TrustCertificate> untrustedCertificates,
			final ValidationService unknownCertificatesService) {
		return new ValidationService() {
			@Override
			public ValidationResult query(final TrustCertificate certificate) {
				if (trustedCertificates != null &&
						trustedCertificates.contains(certificate))
					return ValidationResult.TRUSTED;

				if (untrustedCertificates != null &&
						untrustedCertificates.contains(certificate))
					return ValidationResult.UNTRUSTED;

				if (unknownCertificatesService != null)
					return unknownCertificatesService.query(certificate);

				return ValidationResult.UNKNOWN;
			}
		};
	}

	/**
	 * @returna {@link ValidationService} instance that will always return the
	 * given result
	 * @param result the validation result that is to be returned from the
	 * {@link ValidationService}
	 */
	public static ValidationService getValidationService(
			final ValidationResult result) {
		return new ValidationService() {
			@Override
			public ValidationResult query(final TrustCertificate certificate) {
				return result;
			}
		};
	}

	/**
	 * @return A list of files from well-known locations that can be used to
	 * bootstrap the trust view using {@link #getBoostrapService(File)}.
	 */
	public static List<File> findBoostrapBaseFiles() {
		List<File> bootstrapBases = new ArrayList<>();
		bootstrapBases.addAll(FirefoxBootstrapService.findBootstrapBases());
		bootstrapBases.addAll(ChromiumBootstrapService.findBootstrapBases());
		return bootstrapBases;
	}

	/**
	 * @return a service that can be used to bootstrap the trust view
	 * @param bootstrapBase the file or directory which the bootstrapping
	 * should be based on
	 * @throws UnsupportedOperationException if the given bootstrap base
	 * cannot be used for bootstrapping the trust view
	 */
	public static BootstrapService getBootstrapService(File bootstrapBase) {
		if (FirefoxBootstrapService.canUseAsBootstrapBase(bootstrapBase))
			return new FirefoxBootstrapService(bootstrapBase);

		if (ChromiumBootstrapService.canUseAsBootstrapBase(bootstrapBase))
			return new ChromiumBootstrapService(bootstrapBase);

		throw new UnsupportedOperationException(
				"The given argument is no legal bootstrapping base directory or file: " +
				bootstrapBase);
	}
}
