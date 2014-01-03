package util;

public final class Option<T> {
	private final T value;
	
	public Option() {
		this.value = null;
	}
	
	public Option(T value) {
		this.value = value;
	}
	
	public T get() {
		if (value == null)
			throw new OptionNotSetException();
		return value;
	}

	@Override
	public int hashCode() {
		return value == null ? 0 : value.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Option<?> other = (Option<?>) obj;
		if (value == null) {
			if (other.value != null)
				return false;
		}
		else if (!value.equals(other.value))
			return false;
		return true;
	}

	@Override
	public String toString() {
		if (value == null)
			return "Option[]";
		else
			return "Option[" + value + "]";
	}
}
