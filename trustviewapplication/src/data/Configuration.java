package data;

public interface Configuration extends AutoCloseable {
	static String OPINION_N = "opinion-n";
	static String OPINION_MAX_F = "opinion-max-f";
	static String FIX_KL = "fix-kl";
	static String ASSESSMENT_EXPIRATION_MILLIS = "assessment-expiration-millis";

	public <T> T get(String key, Class<T> type)
			throws ConfigurationValueException;

	public <T> void set(String key, T value)
			throws ConfigurationValueException, UnsupportedOperationException;
}
