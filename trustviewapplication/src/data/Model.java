package data;

import java.io.File;
import java.io.InputStream;
import java.util.Properties;

import data.file.PropertiesFileBackedConfiguration;
import data.sqlite.SQLiteBackedModel;

public final class Model {
	private static SQLiteBackedModel model = null;
	private static Configuration configuration = null;

	private static synchronized SQLiteBackedModel getModel() throws Exception {
		if (model == null)
			model = new SQLiteBackedModel();
		return model;
	}

	private static synchronized Configuration getConfiguration() throws Exception {
		if (configuration == null) {
			Properties properties = new Properties();
			try (InputStream stream =
					Model.class.getResourceAsStream("/configuration.properties")) {
				properties.load(stream);
			}
			configuration = new PropertiesFileBackedConfiguration(properties);
		}
		return configuration;
	}

	private Model() { }

	/**
	 * Opens a {@link TrustView} that can be used to retrieve and/or store
	 * information and must be closed afterwards in order for any modification
	 * made on the <code>TrustView</code> to take effect.
	 *
	 * Note: closing the <code>TrustView</code> may fail in case of concurrent
	 * modifications.
	 *
	 * @return the open <code>TrustView</code> instance
	 *
	 * @throws Exception if the <code>TrustView</code> could not be opened
	 */
	public static TrustView openTrustView() throws Exception {
		return getModel().openTrustView();
	}

	/**
	 * Opens a {@link Configuration} that can be used to retrieve and/or store
	 * information and must be closed afterwards in order for any modification
	 * made on the <code>Configuration</code> to take effect.
	 *
	 * Note: closing the <code>Configuration</code> may fail in case of concurrent
	 * modifications.
	 *
	 * @return the open <code>Configuration</code> instance
	 *
	 * @throws Exception if the <code>Configuration</code> could not be opened
	 */
	public static Configuration openConfiguration() throws Exception {
		final Configuration configuration = getModel().openConfiguration();
		final Configuration defaultConfiguration = getConfiguration();

		return new Configuration() {
			@Override
			public <T> T get(String key, Class<T> type) {
				try {
					return configuration.get(key, type);
				}
				catch (ConfigurationValueException e) {
					return defaultConfiguration.get(key, type);
				}
			}

			@Override
			public <T> void set(String key, T value) {
				configuration.set(key, value);
			}

			@Override
			public void close() throws Exception {
				configuration.close();
			}
		};
	}

	/**
	 * Creates a backup of the current data model and saves it to the given file
	 *
	 * @param file
	 * @throws Exception if the backup file could not be created
	 */
	public static void backup(File file) throws Exception {
		getModel().backup(file);
	}

	/**
	 * Restores a previously saved backup and replaces the contents of the
	 * current data model with the contents stored in the given file
	 *
	 * @param file
	 * @throws Exception if the backup could not be restored
	 */
	public static void restore(File file) throws Exception {
		getModel().restore(file);
	}
}
