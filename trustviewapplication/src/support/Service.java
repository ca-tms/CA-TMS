package support;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
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

import data.CRLInfo;
import data.OCSPInfo;
import data.TrustCertificate;

import sslcheck.core.NotaryManager;
import sslcheck.core.TLSConnectionInfo;
import support.bootstrap.ChromiumBootstrapService;
import support.bootstrap.FirefoxBootstrapService;
import support.revocation.CRL;
import support.revocation.OCSP;
import util.Option;
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
				if (certificate.getCertificate() == null)
					return ValidationResult.UNKNOWN;

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
					System.err.println(
							"Validation service query failed. " +
							"Assuming result is unknown.");
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
					System.err.println(
							"Validation service time-limited query failed. " +
							"Assuming result is unknown.");
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
	 * @return {@link ValidationService} instance that will always return the
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
	 * @return a {@link RevocationService} instance that can be used to download
	 * and query the given Certificate Revocation List
	 * @param info information on where the CRL can be retrieved from
	 */
	public static RevocationService getRevocationService(final CRLInfo info) {
		return getRevocationService(info, -1);
	}

	/**
	 * @return a {@link RevocationService} instance that can be used to download
	 * and query the given Certificate Revocation List using the given timeout
	 * @param info information on where the CRL can be retrieved from
	 * @param timeoutMillis the number of milliseconds which the download
	 * attempt for each CRL file should be cancelled after
	 */
	public static RevocationService getRevocationService(final CRLInfo info,
			final int timeoutMillis) {
		return new RevocationService() {
			private CRLInfo crlInfo = null;

			@Override
			public boolean isRevoked(TrustCertificate certificate) {
				if (crlInfo == null)
					update();

				if (crlInfo == null)
					System.err.println(
							"CRL information not available. " +
							"Assuming certificate is not revoked.");

				if (crlInfo != null && certificate.getCertificate() != null)
					return crlInfo.getCRL().get().isRevoked(certificate.getCertificate());

				return false;
			}

			@Override
			public void update() {
				for (URL url : info.getURLs())
					try {
						CRL crl = timeoutMillis >= 0
								? new CRL(url, info.getCRLIssuer(), timeoutMillis)
								: new CRL(url, info.getCRLIssuer());
						crlInfo = new CRLInfo(
								info.getCRLIssuer(),
								info.getURLs(),
								crl.getNextUpdate(),
								new Option<>(crl.getCRL()));
						break;
					}
					catch (IOException | GeneralSecurityException e) {
						e.printStackTrace();
					}
			}

			@Override
			public Option<Date> getNextUpdate() {
				return (crlInfo != null ? crlInfo : info).getNextUpdate();
			}

			@Override
			public <T> T getInfo(Class<T> infoClass) {
				if (infoClass.isAssignableFrom(CRLInfo.class))
					return infoClass.cast(crlInfo != null ? crlInfo : info);
				return null;
			}
		};
	}

	/**
	 * @return a {@link RevocationService} instance that can be used to query
	 * the given OCSP service
	 * @param info information on where the OCSP service can be reached
	 */
	public static RevocationService getRevocationService(final OCSPInfo info) {
		return getRevocationService(info, -1);
	}

	/**
	 * @return a {@link RevocationService} instance that can be used to query
	 * the given OCSP service
	 * @param info information on where the OCSP service can be reached
	 * @param timeoutMillis the number of milliseconds which the query should be
	 * cancelled after
	 */
	public static RevocationService getRevocationService(final OCSPInfo info,
			final int timeoutMillis) {
		return new RevocationService() {
			private OCSPInfo ocspInfo = null;

			@Override
			public boolean isRevoked(TrustCertificate certificate) {
				for (URL url : info.getURLs())
					try {
						OCSP ocsp = timeoutMillis >= 0
								? new OCSP(url, info.getCertificateIssuer(), timeoutMillis)
								: new OCSP(url, info.getCertificateIssuer());

						boolean isRevoked = ocsp.isRevoked(certificate);

						ocspInfo = new OCSPInfo(
								info.getCertificateIssuer(),
								info.getURLs(),
								ocsp.getNextUpdate());
						return isRevoked;
					}
					catch (IOException | GeneralSecurityException e) {
						e.printStackTrace();
					}

				System.err.println(
						"OCSP services unreachable. " +
						"Assuming certificate is not revoked.");
				return false;
			}

			@Override
			public void update() {
				// nothing to do here for OCSP
			}

			@Override
			public Option<Date> getNextUpdate() {
				return (ocspInfo != null ? ocspInfo : info).getNextUpdate();
			}

			@Override
			public <T> T getInfo(Class<T> infoClass) {
				if (infoClass.isAssignableFrom(OCSPInfo.class))
					return infoClass.cast(ocspInfo != null ? ocspInfo : info);
				return null;
			}
		};
	}

	/**
	 * @return a {@link RevocationService} instance that can be used in
	 * conjunction with another {@link RevocationService} to cache the query
	 * result of that service for further queries
	 * @param revocationService the revocation service that will be used to
	 * query a revocation result
	 */
	public static RevocationService getRevocationService(
			final RevocationService revocationService) {
		final Map<TrustCertificate, Boolean> cache = new HashMap<>();
		return new RevocationService() {
			@Override
			public boolean isRevoked(TrustCertificate certificate) {
				Boolean result = cache.get(certificate);
				if (result != null)
					return result;

				result = revocationService.isRevoked(certificate);
				cache.put(certificate, result);
				return result;
			}

			@Override
			public void update() {
				revocationService.update();
			}

			@Override
			public Option<Date> getNextUpdate() {
				return revocationService.getNextUpdate();
			}

			@Override
			public <T> T getInfo(Class<T> infoClass) {
				return revocationService.getInfo(infoClass);
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
