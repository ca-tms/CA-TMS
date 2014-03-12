package data;

public class ModelAccessException extends Exception {
	private static final long serialVersionUID = -4988969206288878607L;

	public ModelAccessException(Throwable cause) {
		super("Error accessing the data model", cause);
	}

	public ModelAccessException() { }

	public ModelAccessException(String message) {
		super(message);
	}

	public ModelAccessException(String message, Throwable cause) {
		super(message, cause);
	}

	public ModelAccessException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
