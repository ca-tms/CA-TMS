package data.sqlite;

import java.io.File;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.sqlite.SQLiteConnectionPoolDataSource;

import biz.source_code.miniConnectionPoolManager.MiniConnectionPoolManager;

import util.Util;

public class SQLiteBackedModel {
	private static final String DATABASE_FILE_NAME = "ctms.sqlite";
	private static final int MAX_CONNECTIONS = 16;

	private MiniConnectionPoolManager poolManager;

	public SQLiteBackedModel() throws ClassNotFoundException, SQLException {
		final String dir = Util.getDataDirectory() + File.separator + "ctms";
		final String file = dir + File.separator + DATABASE_FILE_NAME;

		new File(dir).mkdirs();

		SQLiteConnectionPoolDataSource dataSource = new SQLiteConnectionPoolDataSource();
		dataSource.setUrl("jdbc:sqlite:" + file);
		poolManager = new MiniConnectionPoolManager(dataSource, MAX_CONNECTIONS);

		try (Connection connection = poolManager.getConnection();
		     Statement statement = connection.createStatement()) {
			connection.setAutoCommit(false);

			statement.execute(
					"CREATE TABLE IF NOT EXISTS assessments (" +
						"k VARCHAR NOT NULL," +
						"ca VARCHAR NOT NULL," +
						"o_kl_t REAL," +
						"o_kl_c REAL," +
						"o_kl_f REAL," +
						"o_it_ca_t REAL NOT NULL," +
						"o_it_ca_c REAL NOT NULL," +
						"o_it_ca_f REAL NOT NULL," +
						"o_it_ee_t REAL NOT NULL," +
						"o_it_ee_c REAL NOT NULL," +
						"o_it_ee_f REAL NOT NULL," +
						"timestamp DATETIME NOT NULL," +
						"" +
						"CHECK (o_kl_t BETWEEN 0 AND 1)," +
						"CHECK (o_kl_c BETWEEN 0 AND 1)," +
						"CHECK (o_kl_f BETWEEN 0 AND 1)," +
						"CHECK (o_it_ca_t BETWEEN 0 AND 1)," +
						"CHECK (o_it_ca_c BETWEEN 0 AND 1)," +
						"CHECK (o_it_ca_f BETWEEN 0 AND 1)," +
						"CHECK (o_it_ee_t BETWEEN 0 AND 1)," +
						"CHECK (o_it_ee_c BETWEEN 0 AND 1)," +
						"CHECK (o_it_ee_f BETWEEN 0 AND 1)," +
						"" +
						"PRIMARY KEY (k))");

			statement.execute(
					"CREATE TABLE IF NOT EXISTS certificates (" +
						"serial VARCHAR NOT NULL," +
						"issuer VARCHAR NOT NULL," +
						"subject VARCHAR NOT NULL," +
						"publickey VARCHAR NOT NULL," +
						"trusted BOOLEAN NOT NULL," +
						"untrusted BOOLEAN NOT NULL," +
						"S BOOLEAN NOT NULL," +
						"" +
						"CHECK (S IN (0, 1))," +
						"CHECK (trusted IN (0, 1))," +
						"CHECK (untrusted IN (0, 1))," +
						"CHECK (NOT (trusted = 1 AND untrusted = 1))," +
						"" +
						"PRIMARY KEY (serial, issuer))");

			connection.commit();
		}
	}

	public SQLiteBackedTrustView openTrustView() throws SQLException {
		Connection connection = poolManager.getConnection();
		connection.setAutoCommit(false);
		return new SQLiteBackedTrustView(connection);
	}
}
