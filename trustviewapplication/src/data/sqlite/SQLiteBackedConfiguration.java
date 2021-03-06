/*
 * This file is part of the CA Trust Management System (CA-TMS)
 *
 * Copyright 2015 by CA-TMS Team.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
 * 
 * @author Pascal Weisenburger
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
				close();
			}
			catch (Throwable u) {
				t.addSuppressed(u);
			}
			throw t;
		}
	}

	@Override
	public boolean exists(String key) {
		try {
			validateDatabaseConnection();

			getValue.setString(1, key);
			try (ResultSet result = getValue.executeQuery()) {
				if (result.next())
					return true;
			}

			return false;
		}
		catch (SQLException e) {
			e.printStackTrace();
		}

		throw new ConfigurationValueAccessException(key);
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
	public void save() throws ModelAccessException {
		try {
			connection.commit();
		}
		catch (SQLException e) {
			throw new ModelAccessException(e);
		}
		finally {
			close();
		}
	}

	@Override
	public void close() throws ModelAccessException {
		try {
			try {
				getValue.close();
				deleteValue.close();
				eraseConfiguration.close();
			}
			finally {
				if (!connection.isClosed()) {
					connection.rollback();
					connection.close();
				}
			}
		}
		catch (SQLException e) {
			throw new ModelAccessException(e);
		}
	}

	private void validateDatabaseConnection() throws SQLException {
		if (connection.isClosed())
			throw new UnsupportedOperationException(
					"Cannot access a Configuration that is already closed.");
	}
}
