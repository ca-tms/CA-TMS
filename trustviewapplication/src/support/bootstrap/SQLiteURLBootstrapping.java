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
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.sqlite.SQLiteDataSource;

import support.BootstrapService.Observer;

/**
 * @author Pascal Weisenburger
 */
final class SQLiteURLBootstrapping {
	private SQLiteURLBootstrapping() { }

	public static void bootstrap(double securityLevel, Observer observer,
			String bootstrappingDescription, String sqlCount, String sqlUrls,
			File... databaseFiles) {
		for (File databaseFile: databaseFiles)
			bootstrap(securityLevel, observer, bootstrappingDescription,
					sqlCount, sqlUrls, databaseFile);
	}

	private static void bootstrap(double securityLevel, Observer observer,
			String bootstrappingDescription, String sqlCount, String sqlUrls,
			File databaseFile) {
		System.out.println("Performing bootstrapping ...");
		System.out.println("  Bootstrapping base: " + bootstrappingDescription);
		System.out.println("  Database: " + databaseFile.getPath());

		SQLiteDataSource dataSource = new SQLiteDataSource();
		dataSource.setUrl("jdbc:sqlite:" + databaseFile.getPath());
		try (Connection connection = dataSource.getConnection();
			 Statement statementCount = connection.createStatement();
			 ResultSet resultCount = statementCount.executeQuery(sqlCount);
			 Statement statement = connection.createStatement();
			 ResultSet result = statement.executeQuery(sqlUrls)) {

			resultCount.next();
			if (!URLBootstrapping.bootstrap(
					URLBootstrapping.iterator(result, 1),
					resultCount.getInt(1),
					securityLevel,
					observer)) {
				System.out.println("Bootstrapping canceled.");
				System.out.println("  Bootstrapping base: " + bootstrappingDescription);
				System.out.println("  Database: " + databaseFile.getPath());
				return;
			}
		}
		catch (Exception e) {
			System.out.println("Bootstrapping failed.");
			System.out.println("  Bootstrapping base: " + bootstrappingDescription);
			System.out.println("  Database: " + databaseFile.getPath());

			e.printStackTrace();
			return;
		}

		System.out.println("Bootstrapping completed.");
		System.out.println("  Bootstrapping base: " + bootstrappingDescription);
		System.out.println("  Database: " + databaseFile.getPath());
	}

	public static boolean areTablesPresent(File databaseFile, String... tableNames) {
		SQLiteDataSource dataSource = new SQLiteDataSource();
		dataSource.setUrl("jdbc:sqlite:" + databaseFile.getPath());
		try (Connection connection = dataSource.getConnection();
			 PreparedStatement statement = connection.prepareStatement(
					"SELECT name FROM sqlite_master WHERE " +
					"type='table' AND name=?")) {
			for (String tableName : tableNames) {
				statement.setString(1, tableName);
				if (!statement.executeQuery().next())
					return false;
			}
		}
		catch (SQLException e) {
			return false;
		}
		return true;
	}
}
