package support.notaries;

import java.security.cert.Certificate;

import util.ValidationResult;

/**
 * This class represents an abstract notary service and defines the required interface.
 */
public interface Notary {
	/**
	 * Query the notary service.
	 * @param cert the certificate to validate by the notary
	 * @return the validation result as an integer, according to the defined constants
	 */
	public abstract ValidationResult queryNotary(Certificate cert);
}
