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
				type == Integer.class ? Integer.valueOf(value) :
				type == Long.class ? Long.valueOf(value) :
				type == Double.class ? Double.valueOf(value) :
				type == Float.class ? Float.valueOf(value) :
				type == Short.class ? Short.valueOf(value) :
				type == Byte.class ? Byte.valueOf(value) : (Object) null);

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
