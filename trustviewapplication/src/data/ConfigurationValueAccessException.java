package data;

/**
 * Indicates that accessing the configuration data failed,
 * a value key does not exist or cannot interpreted as the given type
 */
public class ConfigurationValueAccessException extends RuntimeException {
	private static final long serialVersionUID = -673967580141430801L;
	private static final String message = "Failed to access configuration key: ";

	public ConfigurationValueAccessException() { }

	public ConfigurationValueAccessException(String key) {
		super(message + key);
	}

	public ConfigurationValueAccessException(String key, Throwable cause) {
		super(message + key, cause);
	}

	public ConfigurationValueAccessException(String key, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message + key, cause, enableSuppression, writableStackTrace);
	}
}
