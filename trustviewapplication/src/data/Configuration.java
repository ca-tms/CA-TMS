package data;

/**
 * <p>Provides access to a key-value mapping storage.
 * The known values used in the application are specified as static
 * {@link String} constants, that should be used for the
 * <code>key</code> argument of the interface's methods.</p>
 *
 * <p>A <code>Configuration</code> object must be closed after usage in order for
 * any modification made on the <code>Configuration</code> to take effect and
 * to release acquired resources.</p>
 *
 * <p>Closing the <code>Configuration</code> object may fail in case of concurrent
 * modifications.</p>
 */
public interface Configuration extends AutoCloseable {
	static String OPINION_N = "opinion-n";
	static String OPINION_MAX_F = "opinion-max-f";
	static String FIX_KL = "fix-kl";
	static String SECURITY_LEVEL_LOW = "security-level-low";
	static String SECURITY_LEVEL_MEDIUM = "security-level-medium";
	static String SECURITY_LEVEL_HIGH = "security-level-high";
	static String ASSESSMENT_EXPIRATION_MILLIS = "assessment-expiration-millis";
	static String SERVER_PORT = "server-port";
	static String SERVER_REQUEST_TIMEOUT_MILLIS = "server-request-timeout-millis";

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
	 * @return the value associated with the given key as the specified type.
	 * Supported types are the primitive Java data types and the
	 * @throws UnsupportedOperationException if the underlying implementation
	 * is read-only and does not permit changing values} type.
	 *
	 * @param key
	 * @param type
	 * @throws ConfigurationValueAccessException if the key does not exist, the
	 * value cannot be interpreted as the given type or storage access failed
	 */

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

	@Override
	void close() throws ModelAccessException;
}
