package services.logic;

import java.util.concurrent.CancellationException;
import java.util.concurrent.locks.ReentrantLock;

import support.Service;
import support.ValidationService;
import util.CertificatePathValidity;
import util.ValidationResult;
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
	public static ValidationResult validate(ValidationRequest request)
			throws ModelAccessException {
		ValidationResult result = ValidationResult.UNTRUSTED;

		try {
			if (request.getCertificatePathValidity() == CertificatePathValidity.VALID) {
				System.out.println("Performing trust validation ...");
				System.out.println("  URL: " + request.getURL());
				System.out.println("  Security Level: " + request.getsecurityLevel());

				int attempts = 0;
				while (true) {
					try (TrustView trustView = Model.openTrustView();
					     Configuration config = Model.openConfiguration()) {

						// initialize validation service
						// normally external notaries are queried but the validation
						// service result can be forced to be a given outcome for
						// testing purposes
						String overrideValidationServiceResult =
								config.get(Configuration.OVERRIDE_VALIDATION_SERVICE_RESULT, String.class);

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

						long validationTimeoutMillis =
								config.get(Configuration.VALIDATION_TIMEOUT_MILLIS, Long.class);

						ValidationService validationService =
								validationServiceResult == null ?
									Service.getValidationService(request.getURL(), validationTimeoutMillis) :
									new ValidationService() {
										@Override
										public ValidationResult query(TrustCertificate certificate) {
											return validationServiceResult;
										}
									};

						// perform trust validation
						result = TrustComputation.validate(
									trustView, config,
									request.getCertifiactePath(),
									request.getsecurityLevel(),
									validationService);
					}
					catch (ModelAccessException | CancellationException e) {
						if (attempts == 0)
							e.printStackTrace();

						if (++attempts >= MAX_ATTEMPTS) {
							System.err.println(
									"TrustView update failed. " +
									"The TrustView could not be updated. " +
									"The validation request could not be fulfilled.");
							throw e;
						}

						System.err.println(
								"TrustView update failed. " +
								"This may happen due to concurrent access. Retrying ...");

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
					System.out.println("  Security Level: " + request.getsecurityLevel());
					System.out.println("  Result was " + result);
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
}
