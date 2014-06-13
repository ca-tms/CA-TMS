package data.sqlite;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import data.Configuration;
import data.ConfigurationValueAccessException;
import data.ModelAccessException;

/**
 * Implementation of the {@link Configuration} interface that provides
 * writable access to the configuration key-value mapping stored
 * in a SQLite database.
 */
public class SQLiteBackedConfiguration implements Configuration {
	private final Connection connection;
	private final PreparedStatement getValue;
	private final PreparedStatement setValue;
	private final PreparedStatement deleteValue;
	private final PreparedStatement eraseConfiguration;

	public SQLiteBackedConfiguration(Connection connection) throws ModelAccessException {
		try {
			this.connection = connection;

			try {
				getValue = connection.prepareStatement(
						"SELECT * FROM configuration WHERE key=?");

				setValue = connection.prepareStatement(
						"INSERT OR REPLACE INTO configuration VALUES (?, ?)");

				deleteValue = connection.prepareStatement(
						"DELETE FROM configuration WHERE key=?");

				eraseConfiguration = connection.prepareStatement(
						"DELETE FROM configuration");
			}
			catch (SQLException e) {
				throw new ModelAccessException(e);
			}
		}
		catch (Throwable t) {
			try {
				finalizeConnection();
			}
			catch (Throwable u) {
				t.addSuppressed(u);
			}
			throw t;
		}
	}

	@Override
	public <T> T get(String key, Class<T> type) {
		String value = null;
		try {
			validateDatabaseConnection();

			getValue.setString(1, key);
			try (ResultSet result = getValue.executeQuery()) {
				if (result.next())
					value = result.getString(2);
			}

			if (value != null) {
				T result = type.cast(
					type == String.class ? value :
					type == Boolean.class || type == boolean.class ? Boolean.valueOf(value) :
					type == Integer.class || type == int.class ? Integer.valueOf(value) :
					type == Long.class || type == long.class ? Long.valueOf(value) :
					type == Double.class || type == double.class ? Double.valueOf(value) :
					type == Float.class || type == float.class ? Float.valueOf(value) :
					type == Short.class || type == short.class ? Short.valueOf(value) :
					type == Byte.class || type == byte.class ? Byte.valueOf(value) : (Object) null);

				if (result != null)
					return result;
			}
		}
		catch (NumberFormatException e) {
			throw new ConfigurationValueAccessException(key, e);
		}
		catch (SQLException e) {
			e.printStackTrace();
		}

		throw new ConfigurationValueAccessException(key);
	}

	@Override
	public <T> void set(String key, T value) {
		try {
			validateDatabaseConnection();
			setValue.setString(1, key);
			setValue.setString(2, value.toString());
			setValue.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void delete(String key) {
		try {
			validateDatabaseConnection();
			deleteValue.setString(1, key);
			deleteValue.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void erase() {
		try {
			validateDatabaseConnection();
			eraseConfiguration.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void close() throws ModelAccessException {
		try {
			finalizeConnection();
		}
		catch (SQLException e) {
			throw new ModelAccessException(e);
		}
	}

	private void finalizeConnection() throws SQLException {
		try {
			connection.commit();
		}
		catch (SQLException e) {
			connection.rollback();
			throw e;
		}
		finally {
			try {
				getValue.close();
				deleteValue.close();
				eraseConfiguration.close();
			}
			finally {
				connection.close();
			}
		}
	}

	private void validateDatabaseConnection() throws SQLException {
		if (connection.isClosed())
			throw new UnsupportedOperationException(
					"Cannot access a Configuration that is already closed.");
	}
}
