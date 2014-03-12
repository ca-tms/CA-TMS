package services.logic;

import buisness.TrustComputation;

import support.Service;
import util.CertificatePathValidity;
import util.ValidationResult;

import data.Configuration;
import data.Model;
import data.ModelAccessException;
import data.TrustView;

public final class Validator {
	static final int MAX_ATTEMPTS = 60;
	static final int WAIT_ATTEMPT_MILLIS = 500;

	private Validator() { }

	public static ValidationResult validate(ValidationRequest request)
			throws ModelAccessException {
		ValidationResult result = ValidationResult.UNTRUSTED;

		if (request.getCertificatePathValidity() == CertificatePathValidity.VALID) {
			int attempts = 0;
			while (true) {
				try (TrustView trustView = Model.openTrustView();
				     Configuration config = Model.openConfiguration()) {
					result = TrustComputation.validate(
								trustView, config,
								request.getCertifiactePath(),
								request.getsecurityLevel(),
								Service.getValidationService());
				}
				catch (Exception e) {
					if (attempts == 0)
						e.printStackTrace();

					if (++attempts >= MAX_ATTEMPTS)
						throw e;

					System.err.println("TrustView update failed. This may happen due to concurrent access. Retrying ...");

					try {
						Thread.sleep(WAIT_ATTEMPT_MILLIS);
					}
					catch (InterruptedException i) {
						i.printStackTrace();
					}
					continue;
				}
				break;
			}
		}

		return result;
	}
}
