package support.bootstrap;

import java.io.File;
import java.io.FilenameFilter;
import java.net.URL;
import java.security.cert.Certificate;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.sqlite.SQLiteDataSource;

import data.ModelAccessException;
import data.TrustCertificate;
import services.logic.ValidationRequest;
import services.logic.Validator;
import support.BootstrapService;
import util.CertificatePathValidity;
import util.Util;

public class FirefoxBootstrapService implements BootstrapService {
	private File bootstrapBase;
	private File databaseFile;

	public FirefoxBootstrapService(File bootstrapBase) {
		this.bootstrapBase = bootstrapBase;
		this.databaseFile = findDatabaseFile(bootstrapBase);
	}

	private static String firefoxProfileName(String dirName) {
		int index = dirName.indexOf('.');
		if (index != -1)
			dirName = dirName.substring(index + 1);
		return dirName;
	}

	private static File findDatabaseFile(File bootstrapBase) {
		File databaseFile = null;

		// bootstrap file could be a database file
		if (bootstrapBase.isFile())
			databaseFile = bootstrapBase;
		else if (bootstrapBase.isDirectory()) {
			// bootstrap file could be a directory containing the database file
			databaseFile = new File(bootstrapBase, "places.sqlite");
			if (!databaseFile.isFile()) {
				// bootstrap file could be the Firefox profile directory
				// we then choose the default profile
				File[] files = bootstrapBase.listFiles(new FilenameFilter() {
					@Override
					public boolean accept(File dir, String name) {
						return firefoxProfileName(name).equals("default");
					}
				});

				for (File file : files)
					if (file.isDirectory()) {
						databaseFile = new File(file, "places.sqlite");
						if (!databaseFile.isFile())
							databaseFile = null;
						else
							break;
					}
			}
		}

		if (databaseFile != null) {
			// check if the file could be accessed as SQLite database
			// and if the expected tables are present
			SQLiteDataSource dataSource = new SQLiteDataSource();
			dataSource.setUrl("jdbc:sqlite:" + databaseFile.getPath());
			try (Connection connection = dataSource.getConnection();
				 Statement statement = connection.createStatement()) {
				ResultSet result;
				result = statement.executeQuery(
						"SELECT name FROM sqlite_master WHERE " +
						"type='table' AND name='moz_places'");
				if (!result.next())
					databaseFile = null;

				result = statement.executeQuery(
						"SELECT name FROM sqlite_master WHERE " +
						"type='table' AND name='moz_historyvisits'");
				if (!result.next())
					databaseFile = null;
			}
			catch (SQLException e) {
				databaseFile = null;
			}
		}

		return databaseFile;
	}

	public static boolean canUseAsBootstrapBase(File bootstrapBase) {
		return findDatabaseFile(bootstrapBase) != null;
	}

	public static List<File> findBootstrapBases() {
		String firefoxProfilesDir = null;

		// find Firefox profile directory
		String OS = System.getProperty("os.name").toUpperCase();
		if (OS.contains("WIN"))
			firefoxProfilesDir = Util.getDataDirectory() + "\\Mozilla\\Firefox\\Profiles";
		else if (OS.contains("MAC"))
			firefoxProfilesDir = Util.getDataDirectory() + "/Firefox/Profiles";
		else if (OS.contains("NUX"))
			firefoxProfilesDir = System.getProperty("user.home") + "/.mozilla/firefox";

		if (firefoxProfilesDir == null)
			firefoxProfilesDir = System.getProperty("user.dir") + "/.mozilla/firefox";

		// each profile is stored in its own sub-directory
		List<File> bootstrapBases = new ArrayList<>();
		for (File file : new File(firefoxProfilesDir).listFiles())
			if (file.isDirectory()) {
				File databaseFile = findDatabaseFile(file);
				if (databaseFile != null)
					bootstrapBases.add(file);
			}

		// sort bootstrap base directories alphabetically by profile name
		// but place default profile first
		Collections.sort(bootstrapBases, new Comparator<File>() {
			@Override
			public int compare(File a, File b) {
				String aName = firefoxProfileName(a.getName());
				String bName = firefoxProfileName(b.getName());

				int aDefault = aName.equals("default") ? 1 : 0;
				int bDefault = bName.equals("default") ? 1 : 0;

				if (aDefault != bDefault)
					return bDefault - aDefault;

				if (!aName.equals(bName))
					return aName.compareTo(bName);

				return a.compareTo(b);
			}
		});

		return bootstrapBases;
	}

	@Override
	public void bootstrap(double securityLevel)
			throws ModelAccessException {
		if (databaseFile == null)
			throw new UnsupportedOperationException(
					"No places.sqlite file found in regard to " + bootstrapBase);

		System.out.println("Performing bootstrapping ...");
		System.out.println("  Bootstrapping base: Firefox browser history");
		System.out.println("  Database: " + databaseFile.getPath());

		SQLiteDataSource dataSource = new SQLiteDataSource();
		dataSource.setUrl("jdbc:sqlite:" + databaseFile.getPath());
		try (Connection connection = dataSource.getConnection();
			 Statement statement = connection.createStatement()) {
			ResultSet result = statement.executeQuery(
					"SELECT url, visit_date " +
					"FROM moz_places JOIN moz_historyvisits ON " +
					"     moz_places.id = moz_historyvisits.place_id " +
					"WHERE moz_places.url LIKE 'https:%' AND last_visit_date > 0 " +
					"ORDER BY visit_date asc");

			// we are going to replay the browser history
			// thus we are going to apply all visited URLs in the correct order
			// even if they contain duplicate hosts
			// although this may not be necessary with respect to the trust
			// computation, we think of the validation algorithm as black-box
			Map<String, List<TrustCertificate>> hostCertificates = new HashMap<>();
			while (result.next()) {
				String url = "";
				String host = "";
				try {
					url = result.getString(1);
					host = new URL(url).getHost();

					System.out.println("Performing bootstrapping validation ...");
					System.out.println("  URL: " + url);
					System.out.println("  Host: " + host);

					List<TrustCertificate> certificates = hostCertificates.get(host);
					if (certificates == null) {
						Certificate[] path = Util.retrieveCertificateChain(host);

						certificates = new ArrayList<>(
								Collections.<TrustCertificate>nCopies(
										path.length, null));

						int i = path.length - 1;
						for (Certificate cert : path)
							certificates.set(i--, new TrustCertificate(cert));

						hostCertificates.put(host, certificates);
					}

					ValidationRequest request = new ValidationRequest(
							url,
							certificates,
							CertificatePathValidity.VALID,
							securityLevel,
							false);

					Validator.validate(request);
				}
				catch (Exception e) {
					System.out.println("Bootstrapping validation failed");
					System.out.println("  URL: " + url);
					System.out.println("  Host: " + host);
					e.printStackTrace();
				}
			}
		}
		catch (SQLException e) {
			System.out.println("Bootstrapping failed.");
			System.out.println("  Bootstrapping base: Firefox browser history");
			System.out.println("  Database: " + databaseFile.getPath());

			e.printStackTrace();
			return;
		}

		System.out.println("Bootstrapping completed.");
		System.out.println("  Bootstrapping base: Firefox browser history");
		System.out.println("  Database: " + databaseFile.getPath());
	}
}
