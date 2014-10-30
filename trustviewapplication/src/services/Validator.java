package services;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.locks.ReentrantLock;

import support.Service;
import support.ValidationService;
import util.CertificatePathValidity;
import buisness.TrustComputation;
import buisness.TrustViewControl;
import data.Configuration;
import data.Model;
import data.ModelAccessException;
import data.TrustCertificate;
import data.TrustView;

/**
 * Validator for {@link ValidationRequest}s
 */
public final class Validator {
	static final int MAX_ATTEMPTS = 60;
	static final int WAIT_ATTEMPT_MILLIS = 500;

	private static final ReentrantLock lock = new ReentrantLock();

	private Validator() { }

	/**
	 * @return the validation result for the given request
	 * @param request
	 * @throws ModelAccessException if accessing the data model,
	 * whose data the validation is based on, failed
	 */
	public static ValidationInformation validate(ValidationRequest request)
			throws ModelAccessException {
		ValidationInformation result = new ValidationInformation(
				ValidationResult.UNKNOWN,
				request.getValidationRequestSpec() ==
					ValidationRequestSpec.RETRIEVE_RECOMMENDATION
						? ValidationResultSpec.RECOMMENDED
						: ValidationResultSpec.VALIDATED);

		try {
			if (request.getCertificatePathValidity() == CertificatePathValidity.VALID ||
					request.getValidationRequestSpec() ==
						ValidationRequestSpec.RETRIEVE_RECOMMENDATION) {

				System.out.println("Performing trust validation ...");
				System.out.println("  URL: " + request.getURL());
				System.out.println("  Security Level: " + request.getSecurityLevel());

				if (request.getValidationRequestSpec() ==
						ValidationRequestSpec.VALIDATE_TRUST_END_CERTIFICATE) {
					System.out.println("User trusts host certificate directly.");
					System.out.println("Adding certificate to the certificate watch list " +
							"bypassing trust validation algorithm.");
				}

				if (request.getValidationRequestSpec() ==
						ValidationRequestSpec.RETRIEVE_RECOMMENDATION)
					System.out.println("Only querying validation services for recommendation.");

				ValidationService validationService = null;

				int attempts = 0;
				while (true) {
					try (TrustView trustView = Model.openTrustView();
					     Configuration config = Model.openConfiguration()) {
						if (validationService == null) {
							final String overrideValidationServiceResult =
									config.get(
										Configuration.OVERRIDE_VALIDATION_SERVICE_RESULT, String.class);
							final long validationTimeoutMillis =
									config.get(
										Configuration.VALIDATION_TIMEOUT_MILLIS, Long.class);

							switch (overrideValidationServiceResult.toLowerCase()) {
							case "trusted":
								validationService =
									Service.getValidationService(ValidationResult.TRUSTED);
								break;
							case "untrusted":
								validationService =
									Service.getValidationService(ValidationResult.UNTRUSTED);
								break;
							case "unknown":
								validationService =
									Service.getValidationService(ValidationResult.UNKNOWN);
								break;
							default:
								validationService =
									Service.getValidationService(
										Service.getValidationService(
											validationTimeoutMillis,
											Service.getValidationService(request.getURL())));
								break;
							}
						}

						result = validate(
								trustView, config, validationService,
								request.getURL(),
								request.getCertificatePath(),
								request.getSecurityLevel(),
								request.getValidationRequestSpec());
					}
					catch (ModelAccessException | CancellationException e) {
						if (attempts == 0)
							e.printStackTrace();

						if (++attempts >= MAX_ATTEMPTS) {
							System.err.println(
									"Trust validation or TrustView update failed. " +
									"The TrustView could not be updated. " +
									"The validation request could not be fulfilled.");
							throw e;
						}

						if (e instanceof CancellationException)
							System.err.println(
									"Trust validation failed due validation service time out. " +
									"Retrying ...");
						else
							System.err.println(
									"Trust validation or TrustView update failed. " +
									"This may happen due to concurrent access. " +
									"Retrying ...");

						if (!lock.isHeldByCurrentThread())
							lock.lock();

						try {
							Thread.sleep(WAIT_ATTEMPT_MILLIS);
						}
						catch (InterruptedException i) {
							i.printStackTrace();
						}
						continue;
					}

					System.out.println("Trust validation completed.");
					System.out.println("  URL: " + request.getURL());
					System.out.println("  Security Level: " + request.getSecurityLevel());
					System.out.println("  Result was " + result.getValidationResult() +
							           " (" + result.getValidationResultSpec() + ")");
					break;
				}
			}
		}
		finally {
			if (lock.isHeldByCurrentThread())
				lock.unlock();
		}

		return result;
	}

	/**
	 * @return the validation result for the given arguments,
	 * this is the underlying implementation for
	 * {@link #validate(ValidationRequest)} that does not implement a retrying
	 * scheme in case of time-outs or conflicts
	 * @param trustView
	 * @param config
	 * @param hostURL
	 * @param certificatePath
	 * @param securityLevel
	 * @param spec
	 */
	private static ValidationInformation validate(TrustView trustView,
			Configuration config, ValidationService validationService,
			String hostURL, List<TrustCertificate> certificatePath,
			double securityLevel, ValidationRequestSpec spec) {
		final ValidationService defaultValidationService = validationService;
		final TrustCertificate hostCertificate =
				certificatePath.get(certificatePath.size() - 1);
		final long watchlistExpirationMillis =
				config.get(Configuration.WATCHLIST_EXPIRATION_MILLIS, Long.class);

		if (spec == ValidationRequestSpec.VALIDATE) {
			boolean bootstrappingMode =
					config.get(Configuration.BOOTSTRAPPING_MODE, Boolean.class);

			if (bootstrappingMode)
				spec = ValidationRequestSpec.VALIDATE_WITH_SERVICES;
			else
				spec = ValidationRequestSpec.VALIDATE_WITHOUT_SERVICES;
		}

		switch (spec) {
		case VALIDATE:
			// this never happens
			assert false;
			break;

		case RETRIEVE_RECOMMENDATION:
		case VALIDATE_WITH_SERVICES:
			// just use the default external validation service
			break;

		case VALIDATE_WITHOUT_SERVICES:
			// if we are should not use validation services, let the
			// validation services always return "unknown"
			// In case the existent information does neither provide a
			// trusted nor an untrusted validation result, the overall
			// result will be "unknown" and no experiences will be collected
			validationService =
				Service.getValidationService(ValidationResult.UNKNOWN);
			break;

		case VALIDATE_TRUST_END_CERTIFICATE:
			// if the user trusts the host certificate directly,
			// we will not run whole trust validation algorithm,
			// but just add the certificate to the watchlist
			trustView.addCertificateToWatchlist(hostCertificate);
			return new ValidationInformation(
					ValidationResult.TRUSTED,
					ValidationResultSpec.VALIDATED_ON_WATCHLIST);
		}

		if (spec == ValidationRequestSpec.RETRIEVE_RECOMMENDATION)
			return new ValidationInformation(
					validationService.query(hostCertificate),
					ValidationResultSpec.RECOMMENDED);

		assert
			spec == ValidationRequestSpec.VALIDATE_WITH_SERVICES ||
			spec == ValidationRequestSpec.VALIDATE_WITHOUT_SERVICES;

		// check if certificate is on the watchlist
		if (trustView.isCertificateOnWatchlist(hostCertificate)) {
			Date now = new Date();
			Date timestamp = trustView.getWatchlistCerrtificateTimestamp(
					hostCertificate);
			if (now.getTime() - timestamp.getTime() >
					watchlistExpirationMillis) {
				// certificate on watchlist has expired
				// the certificate must be checked
				// just proceed with the algorithm and use validation services
				validationService = defaultValidationService;
				trustView.removeCertificateFromWatchlist(hostCertificate);
			}
			else
				// certificate on watchlist has not expired yet
				// as long as the certificate is on the watchlist,
				// assume it is trusted
				return new ValidationInformation(
						ValidationResult.TRUSTED,
						ValidationResultSpec.VALIDATED_ON_WATCHLIST);
		}

		// determine result specification
		ValidationResultSpec resultSpec = TrustViewControl.deriveValidationSpec(
				trustView,
				certificatePath.get(certificatePath.size() - 1),
				hostURL);

		// trust certificate directly if it is issued for the same key
		// by the same CA as a previously trusted certificate
		if (resultSpec == ValidationResultSpec.VALIDATED_EXISTING_EXPIRED_SAME_CA_KEY) {
			validationService = Service.getValidationService(
					Collections.singletonList(hostCertificate), null,
					validationService);
		}

		// validate certificate path
		ValidationResult result = TrustComputation.validate(
				trustView, config,
				certificatePath,
				securityLevel,
				validationService);

		// update trust view host information
		if (result != ValidationResult.UNKNOWN)
			TrustViewControl.insertHostsForCertificate(
					trustView, hostCertificate, hostURL);

		// put certificate on watchlist if it was not validated trusted,
		// but is probably a normal certificate or CA change
		if (result == ValidationResult.UNKNOWN &&
				(resultSpec == ValidationResultSpec.VALIDATED_EXISTING_VALID_SAME_KEY ||
					resultSpec == ValidationResultSpec.VALIDATED_EXISTING_EXPIRED_SAME_CA)) {
			trustView.addCertificateToWatchlist(hostCertificate);
			return new ValidationInformation(
					ValidationResult.TRUSTED,
					ValidationResultSpec.VALIDATED_ON_WATCHLIST);
		}

		return new ValidationInformation(result, resultSpec);
	}
}
