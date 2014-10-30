package util;

/**
 * Represents a validation result specification that contains further
 * information on the validation outcome
 */
public enum ValidationResultSpec {
	/** normal validation result */
	VALIDATED,
	/** the certificate was the first one seen for the respective host; */
	VALIDATED_FIRST_SEEN,
	/** an existing certificate for the respective host has expired or was revoked;
	 *  the new certificate was issued by the same CA as the previous one */
	VALIDATED_EXISTING_EXPIRED_SAME_CA,
	/** an existing certificate for the respective host has expired or was revoked;
	 *  the new certificate was issued by the same CA for the same key as the previous one;
	 *  the validation result should be "valid" */
	VALIDATED_EXISTING_EXPIRED_SAME_CA_KEY,
	/** a valid certificate for the respective host already exists;
	 *  the new certificate was issued by the same CA for a different key as the previous one;
	 *  the validation result should be "valid" */
	VALIDATED_EXISTING_VALID_SAME_CA,
	/** a valid certificate for the respective host already exists;
	 *  the new certificate was issued by a different CA for the same key as the previous one; */
	VALIDATED_EXISTING_VALID_SAME_KEY,
	/** a certificate for the respective host already exists;
	 *  the new certificate was issued by a different CA for a different key as the previous one;
	 *  the validation result should be "valid" */
	VALIDATED_EXISTING,
	/** the certificate is preliminarily trusted because it is on the watchlist */
	VALIDATED_ON_WATCHLIST,
	/** the certificate is revoked */
	VALIDATED_REVOKED,
	/** recommendation result from external validation services, no validation */
	RECOMMENDED
}
