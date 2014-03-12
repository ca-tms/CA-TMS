package data;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import data.file.PropertiesFileBackedConfiguration;
import data.sqlite.SQLiteBackedModel;

public final class Model {
	private static SQLiteBackedModel model = null;
	private static Configuration configuration = null;

	private static synchronized SQLiteBackedModel getModel() throws ModelAccessException {
		if (model == null)
			model = new SQLiteBackedModel();
		return model;
	}

	private static synchronized Configuration getConfiguration() throws ModelAccessException {
		if (configuration == null) {
			Properties properties = new Properties();
			try (InputStream stream =
					Model.class.getResourceAsStream("/configuration.properties")) {
				properties.load(stream);
			}
			catch (IOException e) {
				throw new ModelAccessException(e);
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
	 * @throws ModelAccessException if the <code>TrustView</code> could not be opened
	 */
	public static TrustView openTrustView() throws ModelAccessException {
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
	 * @throws ModelAccessException if the <code>Configuration</code> could not be opened
	 */
	public static Configuration openConfiguration() throws ModelAccessException {
		final Configuration configuration = getModel().openConfiguration();
		final Configuration defaultConfiguration = getConfiguration();

		return new Configuration() {
			@Override
			public <T> T get(String key, Class<T> type) {
				try {
					return configuration.get(key, type);
				}
				catch (ConfigurationValueAccessException e) {
					return defaultConfiguration.get(key, type);
				}
			}

			@Override
			public <T> void set(String key, T value) {
				configuration.set(key, value);
			}

			@Override
			public void close() throws ModelAccessException {
				configuration.close();
			}

			@Override
			public void delete(String key) {
				configuration.delete(key);
			}

			@Override
			public void erase() {
				configuration.erase();
			}
		};
	}

	/**
	 * Creates a backup of the current data model and saves it to the given file
	 *
	 * @param file
	 * @throws ModelAccessException if the backup file could not be created
	 */
	public static void backup(File file) throws ModelAccessException {
		getModel().backup(file);
	}

	/**
	 * Restores a previously saved backup and replaces the contents of the
	 * current data model with the contents stored in the given file
	 *
	 * @param file
	 * @throws ModelAccessException if the backup could not be restored
	 */
	public static void restore(File file) throws ModelAccessException {
		getModel().restore(file);
	}

	/**
	 * Erases the all data stored from model (including trust view data and
	 * configuration data)
	 *
	 * @throws ModelAccessException if the model could not be erased
	 */
	public static void erase() throws ModelAccessException {
		getModel().erase();
	}
}
