package util;

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
