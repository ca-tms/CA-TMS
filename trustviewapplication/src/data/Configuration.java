package data;

public interface Configuration extends AutoCloseable {
	static String ASSESSMENT_EXPIRATION_MILLIS = "assessment-expiration-millis";

	public <T> T get(String key, Class<T> type)
			throws ConfigurationValueException;

	public <T> void set(String key, T value)
			throws ConfigurationValueException, UnsupportedOperationException;
}
