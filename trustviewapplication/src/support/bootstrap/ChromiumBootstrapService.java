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
package support.bootstrap;

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import data.ModelAccessException;
import support.BootstrapService;
import util.Util;

/**
 * @author Pascal Weisenburger
 * @author Gregor Rynkowski
 */
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
