package util;

/**
 * Represents a validation result specification that contains further
 * information on the validation outcome
 */
public enum ValidationResultSpec {
	/** normal validation result */
	VALIDATED,
	/** recommendation result from external validation services, no validation */
	RECOMMENDED
}
