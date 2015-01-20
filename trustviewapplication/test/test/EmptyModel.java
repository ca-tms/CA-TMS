package test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import data.Configuration;
import data.ConfigurationValueAccessException;
import data.Model;
import data.ModelAccessException;
import data.TrustView;
import data.file.PropertiesFileBackedConfiguration;
import data.sqlite.SQLiteBackedModel;

public final class EmptyModel implements AutoCloseable {
	private static final String DATABASE_FILE_NAME =
			"catms-test-working-dir" + File.separator + "catms.sqlite";
	private static final String DEFAULT_CONFIGURATION_FILE_NAME =
			"/configuration.properties";

	private SQLiteBackedModel model;
	private Configuration defaultConfiguration;

	public EmptyModel() throws ModelAccessException {
		File databseFile = new File(DATABASE_FILE_NAME);

		databseFile.delete();
		model = new SQLiteBackedModel(databseFile);

		Properties properties = new Properties();
		try (InputStream stream =
				Model.class.getResourceAsStream(DEFAULT_CONFIGURATION_FILE_NAME)) {
			properties.load(stream);
			defaultConfiguration = new PropertiesFileBackedConfiguration(properties);
		}
		catch (IOException e) {
			throw new ModelAccessException(e);
		}

	}

	public TrustView openTrustView() throws ModelAccessException {
		return model.openTrustView();
	}

	public Configuration openConfiguration() throws ModelAccessException {
		final Configuration configuration = model.openConfiguration();

		return new Configuration() {
			@Override
			public boolean exists(String key) {
				return configuration.exists(key) || defaultConfiguration.exists(key);
			}

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
			public void delete(String key) {
				configuration.delete(key);
			}

			@Override
			public void erase() {
				configuration.erase();
			}

			@Override
			public void save() throws ModelAccessException {
				configuration.save();
			}

			@Override
			public void close() throws ModelAccessException {
				configuration.close();
			}
		};
	}

	@Override
	public void close() throws Exception {
		model.close();
		defaultConfiguration.close();
	}
}
