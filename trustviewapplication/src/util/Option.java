package util;

/**
 * Represents an object which can optionally hold a value
 * but does not have to do so making the optionality explicit
 * not relying on <code>null</code> values whose possible validity as a value
 * cannot be seen by inspecting a field's or method's signature
 *
 * @param <T> the type of the value the <code>Option</code> object can hold
 */
public final class Option<T> {
	private final T value;

	/**
	 * Creates a new <code>Option</code> instance that has no value set
	 */
	public Option() {
		this.value = null;
	}

	/**
	 * Creates a new <code>Option</code> instance with the given value set
	 */
	public Option(T value) {
		this.value = value;
	}

	/**
	 * @return <code>true</code> if this object holds a value
	 */
	public boolean isSet() {
		return value != null;
	}

	/**
	 * @return the value this object holds
	 * @throws OptionNotSetException if the object does not hold a value
	 */
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
