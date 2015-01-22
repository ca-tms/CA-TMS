package services;

/**
 * Represents a validation query specification that contains further
 * instructions on how the validation is requested to be carried out
 */
public enum ValidationRequestSpec {
	/** default validation scheme,
	 *  depends on whether the application is in bootstrapping or regular mode */
	VALIDATE,
	/** validation that is allowed to use external validation services
	 *  (like bootstrapping mode) */
	VALIDATE_WITH_SERVICES,
	/** validation that is not allowed to use external validation services
	 *  (like regular mode) */
	VALIDATE_WITHOUT_SERVICES,
	/** validation that considers the end certificate to be trusted */
	VALIDATE_TRUST_END_CERTIFICATE,
	/** recommendation from external validation services, no validation */
	RETRIEVE_RECOMMENDATION
}
