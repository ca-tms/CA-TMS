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
package data;

/**
 * Indicates that accessing the configuration data failed,
 * a value key does not exist or cannot interpreted as the given type
 * 
 * @author Pascal Weisenburger
 */
public class ConfigurationValueAccessException extends RuntimeException {
	private static final long serialVersionUID = -673967580141430801L;
	private static final String message = "Failed to access configuration key: ";

	public ConfigurationValueAccessException() { }

	public ConfigurationValueAccessException(String key) {
		super(message + key);
	}

	public ConfigurationValueAccessException(String key, Throwable cause) {
		super(message + key, cause);
	}

	public ConfigurationValueAccessException(String key, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message + key, cause, enableSuppression, writableStackTrace);
	}
}
