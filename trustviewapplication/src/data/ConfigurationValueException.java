package data;

public class ConfigurationValueException extends RuntimeException {
	private static final long serialVersionUID = -673967580141430801L;

	public ConfigurationValueException() { }

	public ConfigurationValueException(String key) {
		super("Failed to access configuration key: " + key);
	}

	public ConfigurationValueException(String key, Throwable cause) {
		super("Failed to access configuration key: " + key, cause);
	}
}
