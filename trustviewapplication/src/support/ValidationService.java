package support;

import services.ValidationResult;
import data.TrustCertificate;

/**
 * Represents an external validation service
 *
 * @author Pascal Weisenburger
 */
public interface ValidationService {
	/**
	 * @return the validity of the given certificate as estimated by the
	 * external validation service
	 * @param certificate
	 */
	ValidationResult query(TrustCertificate certificate);
}
