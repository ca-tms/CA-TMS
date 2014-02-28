package data.sqlite;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import data.Configuration;
import data.ConfigurationValueException;

public class SQLiteBackedConfiguration implements Configuration {
	private final Connection connection;
	private final PreparedStatement getValue;

	public SQLiteBackedConfiguration(Connection connection) throws SQLException {
		this.connection = connection;

		getValue = connection.prepareStatement(
				"SELECT * FROM configuration WHERE key=?");
	}

	@Override
	public <T> T get(String key, Class<T> type) {
		String value = null;
		try {
			validateDatabaseConnection();
			getValue.setString(1, key);
			try (ResultSet result = getValue.executeQuery()) {
				if (result.next())
					value = result.getString(1);
			}

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
		catch (SQLException e) {
			e.printStackTrace();
		}

		throw new ConfigurationValueException(key);
	}

	@Override
	public <T> void set(String key, T value) {
		//TODO: implement
	}

	@Override
	public void close() throws SQLException {
		try {
			connection.commit();
		}
		catch (SQLException e) {
			connection.rollback();
			throw e;
		}
		finally {
			getValue.close();
			connection.close();
		}
	}

	private void validateDatabaseConnection() throws SQLException {
		if (connection.isClosed())
			throw new UnsupportedOperationException(
					"Cannot access a Configuration that is already closed.");
	}
}
