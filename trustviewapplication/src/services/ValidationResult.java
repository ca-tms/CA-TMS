package services;

/**
 * Represents a trust validation result
 */
public enum ValidationResult {
	/** the validation subject is considered valid */
	TRUSTED,
	/** the validation subject is considered invalid */
	UNTRUSTED,
	/** the subject validity is unknown */
	UNKNOWN
}
