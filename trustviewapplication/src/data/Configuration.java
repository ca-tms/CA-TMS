package data;

/**
 * <p>Provides access to a key-value mapping storage.
 * The known values used in the application are specified as static
 * {@link String} constants, that should be used for the
 * <code>key</code> argument of the interface's methods.</p>
 *
 * <p>A <code>Configuration</code> object must be saved in order for any
 * modification made on the <code>Configuration</code> to take effect and
 * it must be closed after usage to release acquired resources.</p>
 *
 * <p>Saving the <code>Configuration</code> object may fail in case of
 * concurrent modifications.</p>
 */
public interface Configuration extends AutoCloseable {
	static String OPINION_N = "opinion-n";
	static String OPINION_MAX_F = "opinion-max-f";
	static String FIX_KL = "fix-kl";
	static String SECURITY_LEVEL_LOW = "security-level-low";
	static String SECURITY_LEVEL_MEDIUM = "security-level-medium";
	static String SECURITY_LEVEL_HIGH = "security-level-high";
	static String ASSESSMENT_EXPIRATION_MILLIS = "assessment-expiration-millis";
	static String QUERY_SERVICES_FOR_CA_CERTS = "query-services-for-ca-certs";
	static String BOOTSTRAPPING_MODE = "bootstrapping-mode";
	static String SERVER_PORT = "server-port";
	static String SERVER_REQUEST_TIMEOUT_MILLIS = "server-request-timeout-millis";
	static String VALIDATION_SERVICE_TIMEOUT_MILLIS = "validation-service-timeout-millis";
	static String REVOCATION_CRL_TIMEOUT_MILLIS = "revocation-crl-timeout-millis";
	static String REVOCATION_OCSP_TIMEOUT_MILLIS = "revocation-ocsp-timeout-millis";
	static String REVOCATION_CHECKING_INTERVAL_MILLIS = "revocation-checking-interval-millis";
	static String WATCHLIST_EXPIRATION_MILLIS = "watchlist-expiration-millis";
	static String OVERRIDE_VALIDATION_SERVICE_RESULT = "override-validation-service-result";

	/**
	 * @return Determines whether the given key exists
	 *
	 * @param key
	 */
	boolean exists(String key);

	/**
	 * @return the value associated with the given key as the specified type.
	 * Supported types are the primitive Java data types and the
	 * {@link String} type.
	 *
	 * @param key
	 * @param type
	 * @throws ConfigurationValueAccessException if the key does not exist, the
	 * value cannot be interpreted as the given type or storage access failed
	 */
	<T> T get(String key, Class<T> type)
			throws ConfigurationValueAccessException;

	/**
	 * Sets the given key to the given value.
	 * Supported types are the primitive Java data types and the
	 * {@link String} type.
	 *
	 * @param key
	 * @param value
	 * @throws ConfigurationValueAccessException if storage access failed
	 * @throws UnsupportedOperationException if the underlying implementation
	 * is read-only and does not permit changing values
	 */
	<T> void set(String key, T value)
			throws ConfigurationValueAccessException, UnsupportedOperationException;

	/**
	 * Deletes the value associated with the given key
	 *
	 * @param key
	 * @throws UnsupportedOperationException if the underlying implementation
	 * is read-only and does not permit changing values
	 */
	void delete(String key) throws UnsupportedOperationException;

	/**
	 * Erases the all key-value-pairs
	 *
	 * @throws UnsupportedOperationException if the underlying implementation
	 * is read-only and does not permit changing values
	 */
	void erase() throws UnsupportedOperationException;

	/**
	 * Saves all modifications made to <code>Configuration</code> and closes it
	 */
	void save() throws ModelAccessException;

	@Override
	void close() throws ModelAccessException;
}
