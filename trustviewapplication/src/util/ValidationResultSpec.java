package util;

/**
 * Represents a validation result specification that contains further
 * information on the validation outcome
 */
public enum ValidationResultSpec {
	/** normal validation result */
	VALIDATED,
	/** in regular mode, the certificate was the first one seen for the
	 *  respective host; the validation result should be "unknown" */
	VALIDATED_FIRST_SEEN,
	/** in regular mode, an existing certificate for the respective host has
	 *  expired or was revoked; the new certificate was issued by the same CA as
	 *  the previous one; the validation result should be "unknown" */
	VALIDATED_EXISTING_EXPIRED,
	/** in regular mode, a certificate for the respective host already exists;
	 *  the new certificate was issued by the same CA for the same key as the
	 *  previous one; the system will automatically accept the new certificate;
	 *  the validation result should be "valid" */
	VALIDATED_EXISTING_SAME_CA_KEY,
	/** in regular mode, a certificate for the respective host already exists;
	 *  the new certificate was issued by the same CA for a different key as the
	 *  previous one; the validation result should be "unknown" */
	VALIDATED_EXISTING_SAME_CA,
	/** in regular mode, a certificate for the respective host already exists;
	 *  the new certificate was issued by a different CA for the same key as the
	 *  previous one; the validation result should be "unknown" */
	VALIDATED_EXISTING_SAME_KEY,
	/** in regular mode, a certificate for the respective host already exists;
	 *  the new certificate was issued by a different CA for a different key as
	 *  the previous one; the validation result should be "unknown" */
	VALIDATED_EXISTING,
	/** recommendation result from external validation services, no validation */
	RECOMMENDED
}
