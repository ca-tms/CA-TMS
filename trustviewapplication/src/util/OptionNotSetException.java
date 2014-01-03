package util;

public class OptionNotSetException extends UnsupportedOperationException {
	private static final long serialVersionUID = 5250629400497623675L;

	public OptionNotSetException() { }

	public OptionNotSetException(String s) {
		super(s);
	}
}
