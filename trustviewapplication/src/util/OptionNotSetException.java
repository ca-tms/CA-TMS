package util;

/**
 * Indicates that an {@link Option} object's value was accessed
 * but its value was not set
 */
public class OptionNotSetException extends UnsupportedOperationException {
	private static final long serialVersionUID = 5250629400497623675L;

	public OptionNotSetException() {
		super("No value set");
	}

	public OptionNotSetException(String message) {
		super(message);
	}

	public OptionNotSetException(String message, Throwable cause) {
		super(message, cause);
	}
}
