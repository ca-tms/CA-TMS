package data.sqlite;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import util.Util;

public class SQLiteBackedModel {
	private Connection connection;
	private volatile SQLiteBackedTrustView trustView;

	public SQLiteBackedModel() throws ClassNotFoundException, SQLException {
		final String dir = Util.getDataDirectory() + File.separator + "ctms";
		final String file = dir + File.separator + "ctms.sqlite";

		new File(dir).mkdirs();

		Class.forName("org.sqlite.JDBC");
		connection = DriverManager.getConnection("jdbc:sqlite:" + file);
		connection.setAutoCommit(false);

		Statement statement = connection.createStatement();

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
					"date DATETIME NOT NULL," +
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

		statement.close();
		connection.commit();
	}

	public synchronized SQLiteBackedTrustView openTrustView() throws SQLException {
		if (trustView != null && !trustView.isClosed())
			throw new UnsupportedOperationException(
					"Cannot open a TrustView, while another TrustView is still open");

		return trustView = new SQLiteBackedTrustView(connection);
	}
}
