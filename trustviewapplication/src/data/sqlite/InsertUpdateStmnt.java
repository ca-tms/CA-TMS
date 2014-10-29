package data.sqlite;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;

/**
 * Prepared SQLite statement that provides UPSERT (UPDATE or INSERT
 * functionality to UPDATE existing records or INSERT new records depending on
 * if records with the given primary key already exist
 * @see PreparedStatement
 */
class InsertUpdateStmnt implements AutoCloseable {
	private final int primaryValuesCount;
	private final int allValuesCount;
	private final PreparedStatement insertStatement;
	private final PreparedStatement updateStatement;

	/**
	 * Creates a new <code>InsertUpdateStmnt</code> instance for the given
	 * database connection that updates or inserts a new record with the given
	 * key-value pairs for the primary key values and the key-value pairs for
	 * the other values. Key-value pairs are given by successive elements of the
	 * respective arrays. Placeholder for the {@link PreparedStatement} are
	 * specified by <code>'?'</code> character. Default values that are to be
	 * used for newly inserted records and ignored for updated records are
	 * specified by a string starting with <code>'!'</code> character and
	 * followed by the default value.
	 * @param connection
	 * @param table
	 * @param primaryValues
	 * @param values
	 * @throws SQLException
	 */
	InsertUpdateStmnt(Connection connection, String table,
			String[] primaryValues, String[] values) throws SQLException {
		if (primaryValues.length % 2 != 0 || values.length % 2 != 0)
			throw new IllegalArgumentException("key-value definition count not a multiple of 2");
		if (primaryValues.length == 0)
			throw new IllegalArgumentException("no primary key-value pair given");

		// count parameters
		int primaryValuesCounter = 0;
		int allValuesCounter = 0;

		for (int i = 1; i < primaryValues.length; i+= 2)
			for (int k = 0, l = primaryValues[i].length(); k < l; k++)
				if (primaryValues[i].charAt(k) == '?')
					primaryValuesCounter = ++allValuesCounter;
		for (int i = 1; i < values.length; i+= 2)
			for (int k = 0, l = values[i].length(); k < l; k++)
				if (values[i].charAt(k) == '?')
					++allValuesCounter;

		primaryValuesCount = primaryValuesCounter;
		allValuesCount = allValuesCounter;

		// create insert statement
		StringBuilder builder = new StringBuilder();
		builder.append("INSERT OR IGNORE INTO ");
		builder.append(table);
		builder.append(" (");

		for (int i = 0; i < primaryValues.length; i+= 2) {
			if (i != 0)
				builder.append(", ");
			builder.append(primaryValues[i]);
		}
		for (int i = 0; i < values.length; i+= 2) {
			builder.append(", ");
			builder.append(values[i]);
		}
		builder.append(") VALUES (");

		for (int i = 1; i < primaryValues.length; i+= 2)  {
			if (i != 1)
				builder.append(", ");
			builder.append(primaryValues[i]);
		}
		for (int i = 1; i < values.length; i+= 2) {
			builder.append(", ");
			builder.append(values[i].charAt(0) == '!'
					? values[i].substring(1)
					: values[i]);
		}
		builder.append(")");
		insertStatement = connection.prepareStatement(builder.toString());

		// create update statement
		builder.delete(0, builder.length());
		builder.append("UPDATE ");
		builder.append(table);
		builder.append(" SET ");

		for (int i = 0; i < primaryValues.length; i+= 2) {
			if (i != 0)
				builder.append(", ");
			builder.append(primaryValues[i]);
			builder.append("=");
			builder.append(primaryValues[i + 1]);
		}
		for (int i = 0; i < values.length; i+= 2)
			if (values[i + 1].charAt(0) != '!') {
				builder.append(", ");
				builder.append(values[i]);
				builder.append("=");
				builder.append(values[i + 1]);
			}
		builder.append(" WHERE ");

		for (int i = 0; i < primaryValues.length; i+= 2) {
			if (i != 0)
				builder.append(" AND ");
			builder.append(primaryValues[i]);
			builder.append("=");
			builder.append(primaryValues[i + 1]);
		}
		updateStatement = connection.prepareStatement(builder.toString());
	}

	/**
	 * @see PreparedStatement#executeUpdate()
	 * @return
	 * @throws SQLException
	 */
	public int executeUpdate() throws SQLException {
		int rowsChanged = updateStatement.executeUpdate();
		if (rowsChanged == 0)
			rowsChanged = insertStatement.executeUpdate();
		if (rowsChanged != 1)
			throw new SQLException(
					"Insert/Update should change 1 row, but changed " + rowsChanged);
		return rowsChanged;
	}

	@Override
	public void close() throws SQLException {
		insertStatement.close();
		updateStatement.close();
	}

	/**
	 * @see PreparedStatement#setString(int, String)
	 * @param parameterIndex
	 * @param x
	 * @throws SQLException
	 */
	public void setString(int parameterIndex, String x) throws SQLException {
		insertStatement.setString(parameterIndex, x);
		updateStatement.setString(parameterIndex, x);
		if (parameterIndex <= primaryValuesCount)
			updateStatement.setString(allValuesCount + parameterIndex, x);
	}

	/**
	 * @see PreparedStatement#setBoolean(int, boolean)
	 * @param parameterIndex
	 * @param x
	 * @throws SQLException
	 */
	public void setBoolean(int parameterIndex, boolean x) throws SQLException {
		insertStatement.setBoolean(parameterIndex, x);
		updateStatement.setBoolean(parameterIndex, x);
		if (parameterIndex <= primaryValuesCount)
			updateStatement.setBoolean(allValuesCount + parameterIndex, x);
	}

	/**
	 * @see PreparedStatement#setDouble(int, double)
	 * @param parameterIndex
	 * @param x
	 * @throws SQLException
	 */
	public void setDouble(int parameterIndex, double x) throws SQLException {
		insertStatement.setDouble(parameterIndex, x);
		updateStatement.setDouble(parameterIndex, x);
		if (parameterIndex <= primaryValuesCount)
			updateStatement.setDouble(allValuesCount + parameterIndex, x);
	}

	/**
	 * @see PreparedStatement#setBytes(int, byte[])
	 * @param parameterIndex
	 * @param x
	 * @throws SQLException
	 */
	public void setBytes(int parameterIndex, byte[] x) throws SQLException {
		insertStatement.setBytes(parameterIndex, x);
		updateStatement.setBytes(parameterIndex, x);
		if (parameterIndex <= primaryValuesCount)
			updateStatement.setBytes(allValuesCount + parameterIndex, x);
	}

	/**
	 * @see PreparedStatement#setTimestamp(int, Timestamp)
	 * @param parameterIndex
	 * @param x
	 * @throws SQLException
	 */
	public void setTimestamp(int parameterIndex, Timestamp x) throws SQLException {
		insertStatement.setTimestamp(parameterIndex, x);
		updateStatement.setTimestamp(parameterIndex, x);
		if (parameterIndex <= primaryValuesCount)
			updateStatement.setTimestamp(allValuesCount + parameterIndex, x);
	}

	/**
	 * @see PreparedStatement#setNull(int, int)
	 * @param parameterIndex
	 * @param sqlType
	 * @throws SQLException
	 */
	public void setNull(int parameterIndex, int sqlType) throws SQLException {
		insertStatement.setNull(parameterIndex, sqlType);
		updateStatement.setNull(parameterIndex, sqlType);
		if (parameterIndex <= primaryValuesCount)
			updateStatement.setNull(allValuesCount + parameterIndex, sqlType);
	}
}
