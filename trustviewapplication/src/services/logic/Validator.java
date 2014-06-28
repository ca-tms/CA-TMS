package services.logic;

import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.locks.ReentrantLock;

import support.Service;
import support.ValidationService;
import util.CertificatePathValidity;
import util.ValidationResult;
import util.ValidationResultSpec;
import buisness.TrustComputation;
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
	public static ValidatorResult validate(ValidationRequest request)
			throws ModelAccessException {
		ValidatorResult result = new ValidatorResult(
				ValidationResult.UNKNOWN,
				request.getValidationRequestSpec() ==
				ValidationRequestSpec.RETRIEVE_RECOMMENDATION
						? ValidationResultSpec.RECOMMENDED
						: ValidationResultSpec.VALIDATED);

		try {
			if (request.getCertificatePathValidity() == CertificatePathValidity.VALID) {
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

				int attempts = 0;
				while (true) {
					try (TrustView trustView = Model.openTrustView();
					     Configuration config = Model.openConfiguration()) {
						result = validate(
								trustView, config,
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
							           "(" + result.getValidationResultSpec() + ")");
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
	private static ValidatorResult validate(TrustView trustView,
			Configuration config, String hostURL,
			List<TrustCertificate> certificatePath, double securityLevel,
			ValidationRequestSpec spec) {
		ValidationService validationService = null;

		final String overrideValidationServiceResult =
				config.get(Configuration.OVERRIDE_VALIDATION_SERVICE_RESULT, String.class);
		final long validationTimeoutMillis =
				config.get(Configuration.VALIDATION_TIMEOUT_MILLIS, Long.class);

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

		case VALIDATE_WITH_SERVICES:
			// normally external notaries are queried but the validation
			// service result can be forced to be a given outcome for
			// testing purposes
			final ValidationResult validationServiceResult;
			switch (overrideValidationServiceResult.toLowerCase()) {
			case "trusted":
				validationServiceResult = ValidationResult.TRUSTED;
				break;
			case "untrusted":
				validationServiceResult = ValidationResult.UNTRUSTED;
				break;
			case "unknown":
				validationServiceResult = ValidationResult.UNKNOWN;
				break;
			default:
				validationServiceResult = null;
				break;
			}

			validationService =
					validationServiceResult == null ?
						Service.getValidationService(hostURL, validationTimeoutMillis) :
						new ValidationService() {
							@Override
							public ValidationResult query(TrustCertificate certificate) {
								return validationServiceResult;
							}
						};
			break;

		case VALIDATE_WITHOUT_SERVICES:
			// if we are should not use validation services, let the
			// validation services always return "unknown"
			// In case the existent information does neither provide a
			// trusted nor an untrusted validation result, the overall
			// result will be "unknown" and no experiences will be collected
			validationService = new ValidationService() {
				@Override
				public ValidationResult query(TrustCertificate certificate) {
					return ValidationResult.UNKNOWN;
				}
			};
			break;

		case VALIDATE_TRUST_END_CERTIFICATE:
			// if the user trusts the host certificate directly,
			// we will not run whole trust validation algorithm,
			// but just add the certificate to the watch list

			//TODO add certificate to the watch list instead of trusting it directly

			trustView.setTrustedCertificate(
					certificatePath.get(certificatePath.size() - 1));
			return new ValidatorResult(
					ValidationResult.TRUSTED,
					ValidationResultSpec.VALIDATED);

		case RETRIEVE_RECOMMENDATION:
			validationService =
					Service.getValidationService(hostURL, validationTimeoutMillis);
			return new ValidatorResult(
					validationService.query(
							certificatePath.get(certificatePath.size() - 1)),
					ValidationResultSpec.RECOMMENDED);
		}

		assert
			spec == ValidationRequestSpec.VALIDATE_WITH_SERVICES ||
			spec == ValidationRequestSpec.VALIDATE_WITHOUT_SERVICES;
		assert
			validationService != null;

		ValidationResultSpec resultSpec = ValidationResultSpec.VALIDATED;

		if (spec == ValidationRequestSpec.VALIDATE_WITHOUT_SERVICES) {
			// TODO determine special cases for regular mode
		}

		return new ValidatorResult(
				TrustComputation.validate(
						trustView, config,
						certificatePath,
						securityLevel,
						validationService),
				resultSpec);
	}
}
