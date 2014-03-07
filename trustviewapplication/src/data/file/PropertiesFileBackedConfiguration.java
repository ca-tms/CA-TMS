package data.file;

import java.sql.SQLException;
import java.util.Properties;

import data.Configuration;
import data.ConfigurationValueException;

public class PropertiesFileBackedConfiguration implements Configuration {
	private final Properties properties;

	public PropertiesFileBackedConfiguration(Properties properties) {
		this.properties = properties;
	}

	@Override
	public <T> T get(String key, Class<T> type) {
		String value = properties.getProperty(key);

		try {
			T result = type.cast(
				type == String.class ? value :
				type == Integer.class || type == int.class ? Integer.valueOf(value) :
				type == Long.class || type == long.class ? Long.valueOf(value) :
				type == Double.class || type == double.class ? Double.valueOf(value) :
				type == Float.class || type == float.class ? Float.valueOf(value) :
				type == Short.class || type == short.class ? Short.valueOf(value) :
				type == Byte.class || type == byte.class ? Byte.valueOf(value) : (Object) null);

			if (result != null)
				return result;
		}
		catch (NumberFormatException e) {
			throw new ConfigurationValueException(key, e);
		}

		throw new ConfigurationValueException(key);
	}

	@Override
	public <T> void set(String key, T value) {
		throw new UnsupportedOperationException(
				"PropertiesFileBackedConfiguration is read-only");
	}

	@Override
	public void close() throws SQLException { }
}
