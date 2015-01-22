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
package data.file;

import java.util.Properties;

import data.Configuration;
import data.ConfigurationValueAccessException;
import data.ModelAccessException;

/**
 * Implementation of the {@link Configuration} interface that provides
 * read-only access to the configuration key-value mapping stored
 * in a {@link Properties} file.
 * 
 * @author Pascal Weisenburger
 */
public class PropertiesFileBackedConfiguration implements Configuration {
	private final Properties properties;

	public PropertiesFileBackedConfiguration(Properties properties) {
		this.properties = properties;
	}

	@Override
	public boolean exists(String key) {
		return properties.getProperty(key) != null;
	}

	@Override
	public <T> T get(String key, Class<T> type) {
		String value = properties.getProperty(key);

		try {
			T result = type.cast(
				type == String.class ? value :
				type == Boolean.class || type == boolean.class ? Boolean.valueOf(value) :
				type == Integer.class || type == int.class ? Integer.valueOf(value) :
				type == Long.class || type == long.class ? Long.valueOf(value) :
				type == Double.class || type == double.class ? Double.valueOf(value) :
				type == Float.class || type == float.class ? Float.valueOf(value) :
				type == Short.class || type == short.class ? Short.valueOf(value) :
				type == Byte.class || type == byte.class ? Byte.valueOf(value) : (Object) null);

			if (result != null)
				return result;
		}
		catch (NumberFormatException e) {
			throw new ConfigurationValueAccessException(key, e);
		}

		throw new ConfigurationValueAccessException(key);
	}

	@Override
	public <T> void set(String key, T value) {
		notSupported();
	}

	@Override
	public void delete(String key) {
		notSupported();
	}

	@Override
	public void erase() {
		notSupported();
	}

	@Override
	public void save() throws ModelAccessException { }

	@Override
	public void close() throws ModelAccessException { }

	private void notSupported() {
		throw new UnsupportedOperationException(
				"PropertiesFileBackedConfiguration is read-only");
	}
}
