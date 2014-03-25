package support;

import data.TrustCertificate;

import util.ValidationResult;

/**
 * Represents an external validation service
 */
public interface ValidationService {
	/**
	 * @return the validity of the given certificate as estimated by the
	 * external validation service
	 * @param certificate
	 */
	ValidationResult query(TrustCertificate certificate);
}
