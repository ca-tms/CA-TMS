package services;

import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.locks.ReentrantLock;

import support.Service;
import support.ValidationService;
import util.CertificatePathValidity;
import buisness.RevocationValidation;
import buisness.TrustValidation;
import data.Configuration;
import data.Model;
import data.ModelAccessException;
import data.TrustCertificate;
import data.TrustView;

/**
 * Validator for {@link ValidationRequest}s
 */
public final class Validator {
	static final int MAX_VALIDATION_SERVICE_ATTEMPTS = 3;
	static final int MAX_ATTEMPTS = 60;
	static final int WAIT_ATTEMPT_MILLIS = 500;

	private static final ReentrantLock lock = new ReentrantLock(true);

	private Validator() { }

	/**
	 * @return the validation result for the given request
	 * @param request
	 * @throws ModelAccessException if accessing the data model,
	 * whose data the validation is based on, failed
	 */
	public static ValidationInformation validate(ValidationRequest request)
			throws ModelAccessException {
		final boolean retrieveRecommendation =
				request.getValidationRequestSpec() ==
					ValidationRequestSpec.RETRIEVE_RECOMMENDATION;

		ValidationInformation result = new ValidationInformation(
				ValidationResult.UNKNOWN,
				retrieveRecommendation
						? ValidationResultSpec.RECOMMENDED
						: ValidationResultSpec.VALIDATED);

		try {
			if (request.getCertificatePathValidity() == CertificatePathValidity.VALID ||
					retrieveRecommendation) {

				System.out.println("Performing trust validation ...");
				System.out.println("  URL: " + request.getURL());
				System.out.println("  Security Level: " + request.getSecurityLevel());

				if (request.getValidationRequestSpec() ==
						ValidationRequestSpec.VALIDATE_TRUST_END_CERTIFICATE) {
					System.out.println("User trusts host certificate directly.");
					System.out.println("Adding certificate to the certificate watch list " +
							"bypassing trust validation algorithm.");
				}

				if (retrieveRecommendation)
					System.out.println("Only querying validation services for recommendation.");

				ValidationService validationService = null;
				RevocationValidation.Validator revocationService = null;

				int attempts = 0, validationServiceAttempts = 0;
				while (true) {
					try (TrustView trustView = Model.openTrustView();
					     Configuration config = Model.openConfiguration()) {
						// initialize validation service
						if (validationService == null)
							validationService = constructValidationService(
									config, request.getURL());

						// initialize revocation service
						if (revocationService == null && !retrieveRecommendation)
							revocationService = constructRevocationService(
									config, request.getCertificatePath());

						// perform validation
						if (!retrieveRecommendation &&
								!revocationService.validate(trustView))
							result = new ValidationInformation(
									ValidationResult.UNTRUSTED,
									ValidationResultSpec.VALIDATED_REVOKED);
						else
							result = TrustValidation.validate(trustView, config,
									request, validationService);

						config.close();
						trustView.save();
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

						if (e instanceof CancellationException) {
							if (++validationServiceAttempts >= MAX_VALIDATION_SERVICE_ATTEMPTS) {
								validationService =
									Service.getValidationService(ValidationResult.UNKNOWN);

								System.err.println(
										"Trust validation failed due validation service time out. " +
										"Assuming result is unknown.");
							}
							else
								System.err.println(
										"Trust validation failed due validation service time out. " +
										"Retrying ...");
						}
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
	 * @return a validation service for the given host taking account of the
	 * given configuration
	 * @param config
	 * @param hostURL
	 */
	private static ValidationService constructValidationService(
			Configuration config, String hostURL) {
		final String overrideValidationServiceResult =
				config.get(
					Configuration.OVERRIDE_VALIDATION_SERVICE_RESULT,
					String.class);
		final long validationServiceTimeoutMillis =
				config.get(
					Configuration.VALIDATION_SERVICE_TIMEOUT_MILLIS,
					Long.class);

		ValidationService service;
		ValidationResult overriddenValidationServiceResult = null;

		switch (overrideValidationServiceResult.toLowerCase()) {
		case "trusted":
			overriddenValidationServiceResult = ValidationResult.TRUSTED;
			break;
		case "untrusted":
			overriddenValidationServiceResult = ValidationResult.UNTRUSTED;
			break;
		case "unknown":
			overriddenValidationServiceResult = ValidationResult.UNKNOWN;
			break;
		}

		if (overriddenValidationServiceResult != null) {
			System.out.println("Overriding validation service result: " +
				overriddenValidationServiceResult);
			service =
				Service.getValidationService(overriddenValidationServiceResult);
		}
		else
			service =
				Service.getValidationService(
					Service.getValidationService(
						validationServiceTimeoutMillis,
						Service.getValidationService(hostURL)));

		return service;
	}

	/**
	 * @return the certificates and associated revocation services for the
	 * given certificate path taking account of the given configuration
	 * @param config
	 * @param certificatePath
	 */
	private static RevocationValidation.Validator constructRevocationService(
			Configuration config, List<TrustCertificate> certificatePath) {
		final int crlTimeoutMillis =
				config.get(
					Configuration.REVOCATION_CRL_TIMEOUT_MILLIS,
					Integer.class);
		final int ocspTimeoutMillis =
				config.get(
					Configuration.REVOCATION_OCSP_TIMEOUT_MILLIS,
					Integer.class);

		return RevocationValidation.createValidator(certificatePath,
				crlTimeoutMillis, ocspTimeoutMillis);
	}
}
