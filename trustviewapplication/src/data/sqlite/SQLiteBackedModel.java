package data.sqlite;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteConnectionPoolDataSource;

import data.Model;
import data.ModelAccessException;

import biz.source_code.miniConnectionPoolManager.MiniConnectionPoolManager;

/**
 * Data model that is to be used by the {@link Model} to implement data storage
 * using a SQLite database.
 */
public class SQLiteBackedModel implements AutoCloseable {
	private static final int MAX_CONNECTIONS = 16;

	private MiniConnectionPoolManager poolManager;
	private File databaseFile;

	public SQLiteBackedModel(File databaseFile) throws ModelAccessException {
		this.databaseFile = databaseFile;

		try {
			setup();
		}
		catch (SQLException e) {
			throw new ModelAccessException(e);
		}
	}

	public void setup() throws SQLException {
		databaseFile.getParentFile().mkdirs();

		SQLiteConfig config = new SQLiteConfig();
		config.enforceForeignKeys(true);

		SQLiteConnectionPoolDataSource dataSource = new SQLiteConnectionPoolDataSource();
		dataSource.setUrl("jdbc:sqlite:" + databaseFile.getPath());
		dataSource.setConfig(config);
		poolManager = new MiniConnectionPoolManager(dataSource, MAX_CONNECTIONS);

		try (Connection connection = poolManager.getConnection();
		     Statement statement = connection.createStatement()) {
			connection.setAutoCommit(false);

			statement.execute(
					"CREATE TABLE IF NOT EXISTS assessments (" +
						"k VARCHAR NOT NULL," +          // public key
						"ca VARCHAR NOT NULL," +         // CA name
						"o_kl_t REAL," +                 // key legitimacy
						"o_kl_c REAL," +
						"o_kl_f REAL," +
						"o_kl_r REAL," +
						"o_kl_s REAL," +
						"o_it_ca_t REAL NOT NULL," +     // issuer trust (to sign CAs)
						"o_it_ca_c REAL NOT NULL," +
						"o_it_ca_f REAL NOT NULL," +
						"o_it_ca_r REAL NOT NULL," +
						"o_it_ca_s REAL NOT NULL," +
						"o_it_ee_t REAL NOT NULL," +     // issuer trust (to sign end entities)
						"o_it_ee_c REAL NOT NULL," +
						"o_it_ee_f REAL NOT NULL," +
						"o_it_ee_r REAL NOT NULL," +
						"o_it_ee_s REAL NOT NULL," +
						"timestamp DATETIME NOT NULL," + // last access time
						"" +
						"CHECK (o_kl_t BETWEEN 0 AND 1)," +
						"CHECK (o_kl_c BETWEEN 0 AND 1)," +
						"CHECK (o_kl_f BETWEEN 0 AND 1)," +
						"CHECK (o_kl_r >= 0)," +
						"CHECK (o_kl_s >= 0)," +
						"CHECK (o_it_ca_t BETWEEN 0 AND 1)," +
						"CHECK (o_it_ca_c BETWEEN 0 AND 1)," +
						"CHECK (o_it_ca_f BETWEEN 0 AND 1)," +
						"CHECK (o_it_ca_r >= 0)," +
						"CHECK (o_it_ca_s >= 0)," +
						"CHECK (o_it_ee_t BETWEEN 0 AND 1)," +
						"CHECK (o_it_ee_c BETWEEN 0 AND 1)," +
						"CHECK (o_it_ee_f BETWEEN 0 AND 1)," +
						"CHECK (o_it_ee_r >= 0)," +
						"CHECK (o_it_ee_s >= 0)," +
						"" +
						"PRIMARY KEY (k))");

			statement.execute(
					"CREATE TABLE IF NOT EXISTS certificates (" +
						"serial VARCHAR NOT NULL," +     // serial
						"issuer VARCHAR NOT NULL," +     // issuer
						"subject VARCHAR NOT NULL," +    // subject
						"publickey VARCHAR NOT NULL," +  // public key
						"notbefore DATETIME NOT NULL," + // not before
						"notafter DATETIME NOT NULL," +  // not after
						"certdata BLOB," +               // DER-encoded certificate
						"trusted BOOLEAN NOT NULL," +    // is certificate trusted
						"untrusted BOOLEAN NOT NULL," +  // is certificate untrusted
						"S BOOLEAN NOT NULL," +          // is certificate in the S set
						"" +                             //  of the related assessment
						"CHECK (S IN (0, 1))," +
						"CHECK (trusted IN (0, 1))," +
						"CHECK (untrusted IN (0, 1))," +
						"CHECK (NOT (trusted = 1 AND untrusted = 1))," +
						"" +
						"PRIMARY KEY (serial, issuer))");

			statement.execute(
					"CREATE TABLE IF NOT EXISTS certhosts (" +
						"serial VARCHAR NOT NULL," +     // serial
						"issuer VARCHAR NOT NULL," +     // issuer
						"host VARCHAR NOT NULL," +       // host
						"" +
						"FOREIGN KEY (serial, issuer)" +
						"  REFERENCES certificates(serial, issuer)" +
						"  ON DELETE CASCADE," +
						"PRIMARY KEY (serial, issuer, host))");

			statement.execute(
					"CREATE TABLE IF NOT EXISTS watchlist (" +
						"serial VARCHAR NOT NULL," +     // serial
						"issuer VARCHAR NOT NULL," +     // issuer
						"timestamp DATETIME NOT NULL," + // start watching time
						"" +
						"FOREIGN KEY (serial, issuer)" +
						"  REFERENCES certificates(serial, issuer)" +
						"  ON DELETE CASCADE," +
						"PRIMARY KEY (serial, issuer))");

			statement.execute(
					"CREATE TABLE IF NOT EXISTS configuration (" +
						"key VARCHAR NOT NULL," +    // key
						"value VARCHAR NOT NULL," +  // value of the related key
						"" +
						"PRIMARY KEY (key))");

			connection.commit();
		}
	}

	private void teardown() throws SQLException {
		poolManager.dispose();
		poolManager = null;
	}

	@Override
	public void close() throws Exception {
		teardown();
	}

	public synchronized SQLiteBackedTrustView openTrustView() throws ModelAccessException {
		Connection connection = null;
		try {
			connection = poolManager.getConnection();
			connection.setAutoCommit(false);
			return new SQLiteBackedTrustView(connection);
		}
		catch (SQLException e) {
			try {
				if (connection != null)
					connection.close();
			}
			catch (Throwable t) {
				e.addSuppressed(t);
			}
			throw new ModelAccessException(e);
		}
	}

	public synchronized SQLiteBackedConfiguration openConfiguration() throws ModelAccessException {
		Connection connection = null;
		try {
			connection = poolManager.getConnection();
			connection.setAutoCommit(false);
			return new SQLiteBackedConfiguration(connection);
		}
		catch (SQLException e) {
			try {
				if (connection != null)
					connection.close();
			}
			catch (Throwable t) {
				e.addSuppressed(t);
			}
			throw new ModelAccessException(e);
		}
	}

	public synchronized void backup(File file) throws ModelAccessException {
		try {
			copy(databaseFile, file);
		}
		catch (IOException e) {
			throw new ModelAccessException(e);
		}
	}

	public synchronized void restore(File file) throws ModelAccessException {
		File databaseTempFile = new File(databaseFile.getPath() + ".temp");

		try {
			teardown();
			databaseFile.renameTo(databaseTempFile);
			copy(file, databaseFile);
			setup();
			databaseTempFile.delete();
		}
		catch (SQLException | IOException e) {
			if (databaseTempFile.exists()) {
				databaseFile.delete();
				databaseTempFile.renameTo(databaseFile);
			}
			throw new ModelAccessException(e);
		}
	}

	public synchronized void erase() throws ModelAccessException {
		try {
			teardown();
			databaseFile.delete();
			setup();
		}
		catch (SQLException e) {
			throw new ModelAccessException(e);
		}
	}

	private static void copy(File source, File destination) throws IOException {
		try (FileInputStream inputStream = new FileInputStream(source);
		     FileOutputStream outputStream = new FileOutputStream(destination);
		     FileChannel sourceChannel = inputStream.getChannel();
		     FileChannel destinationChannel = outputStream.getChannel()) {
			destinationChannel.transferFrom(sourceChannel, 0, sourceChannel.size());
		}
	}
}
