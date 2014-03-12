package data;

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

	<T> T get(String key, Class<T> type)
			throws ConfigurationValueAccessException;

	<T> void set(String key, T value)
			throws ConfigurationValueAccessException, UnsupportedOperationException;

	void delete(String key)
			throws UnsupportedOperationException;

	void erase();
}
