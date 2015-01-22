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
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import data.ModelAccessException;
import support.BootstrapService;
import util.Util;

/**
 * @author Pascal Weisenburger
 * @author Gregor Rynkowski
 */
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

		if (databaseFile != null &&
			!SQLiteURLBootstrapping.areTablesPresent(databaseFile,
					"moz_places", "moz_historyvisits"))
				databaseFile = null;

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
	public void bootstrap(double securityLevel, Observer observer)
			throws ModelAccessException {
		if (databaseFile == null)
			throw new UnsupportedOperationException(
					"No places.sqlite file found in regard to " + bootstrapBase);

		SQLiteURLBootstrapping.bootstrap(securityLevel, observer,
				"Firefox browser history",

				"SELECT COUNT(*) " +
				"FROM moz_places JOIN moz_historyvisits ON " +
				"     moz_places.id = moz_historyvisits.place_id " +
				"WHERE moz_places.url LIKE 'https:%' AND last_visit_date > 0",

				"SELECT url " +
				"FROM moz_places JOIN moz_historyvisits ON " +
				"     moz_places.id = moz_historyvisits.place_id " +
				"WHERE moz_places.url LIKE 'https:%' AND last_visit_date > 0 " +
				"ORDER BY visit_date asc",

				databaseFile);
	}
}
