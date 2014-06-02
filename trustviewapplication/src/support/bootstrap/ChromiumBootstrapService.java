package support.bootstrap;

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import data.ModelAccessException;
import support.BootstrapService;
import util.Util;

public class ChromiumBootstrapService implements BootstrapService {
	private File bootstrapBase;
	private File databaseFiles[];

	public ChromiumBootstrapService(File bootstrapBase) {
		this.bootstrapBase = bootstrapBase;
		this.databaseFiles = findDatabaseFiles(bootstrapBase);
	}

	private static File[] findDatabaseFiles(File bootstrapBase) {
		File databaseFile;
		List<File> databaseFiles = new ArrayList<>();

		// bootstrap file could be a database file
		if (bootstrapBase.isFile())
			databaseFiles.add(bootstrapBase);
		else if (bootstrapBase.isDirectory()) {
			// bootstrap file could be a directory containing the database file
			databaseFile = new File(bootstrapBase, "History");
			if (databaseFile.isFile())
				databaseFiles.add(databaseFile);
			databaseFile = new File(bootstrapBase, "Archived History");
			if (databaseFile.isFile())
				databaseFiles.add(databaseFile);

			if (databaseFiles.isEmpty()) {
				// bootstrap file could be the Chromium profile directory
				bootstrapBase = new File(bootstrapBase, "Default");
				databaseFile = new File(bootstrapBase, "History");
				if (databaseFile.isFile())
					databaseFiles.add(databaseFile);
				databaseFile = new File(bootstrapBase, "Archived History");
				if (databaseFile.isFile())
					databaseFiles.add(databaseFile);
			}
		}

		Iterator<File> iterator = databaseFiles.iterator();
		while (iterator.hasNext())
			if (!SQLiteURLBootstrapping.areTablesPresent(iterator.next(),
					"urls", "visits"))
				iterator.remove();

		return databaseFiles.toArray(new File[0]);
	}

	public static boolean canUseAsBootstrapBase(File bootstrapBase) {
		return findDatabaseFiles(bootstrapBase).length != 0;
	}

	public static List<File> findBootstrapBases() {
		File baseDirectories[] = null;

		// find Chromium default directory
		String OS = System.getProperty("os.name").toUpperCase();
		if (OS.contains("WIN"))
			baseDirectories = new File[] {
				new File(System.getenv("LOCALAPPDATA") + "\\Chromium\\User Data\\Default"),
				new File(System.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default")
		};
		else if (OS.contains("MAC"))
			baseDirectories = new File[] {
				new File(Util.getDataDirectory() + "/Chromium/Default"),
				new File(Util.getDataDirectory() + "/Google/Chrome/Default")
			};
		else if (OS.contains("NUX"))
			baseDirectories = new File[] {
				new File(Util.getConfigDirectory() + "/chromium/Default"),
				new File(Util.getConfigDirectory() + "/google-chrome/Default")
			};

		if (baseDirectories == null)
			baseDirectories = new File[] {
				new File(System.getProperty("user.dir") + "/chromium/Default"),
				new File(System.getProperty("user.dir") + "/google-chrome/Default")
			};

		// each profile is stored in its own sub-directory
		List<File> bootstrapBases = new ArrayList<>();
		for (File directory : baseDirectories)
			if (canUseAsBootstrapBase(directory))
				bootstrapBases.add(directory);

		return bootstrapBases;
	}

	@Override
	public void bootstrap(double securityLevel, Observer observer)
			throws ModelAccessException {
		if (databaseFiles.length == 0)
			throw new UnsupportedOperationException(
					"No history file found in regard to " + bootstrapBase);

		SQLiteURLBootstrapping.bootstrap(securityLevel, observer,
				"Chromium browser history",

				"SELECT COUNT(*) " +
				"FROM urls JOIN visits ON " +
				"     urls.id = visits.url " +
				"WHERE urls.url LIKE 'https:%'",

				"SELECT urls.url " +
				"FROM urls JOIN visits ON " +
				"     urls.id = visits.url " +
				"WHERE urls.url LIKE 'https:%' " +
				"ORDER BY visit_time asc",

				databaseFiles);
	}
}
