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
package util;

/**
 * Indicates that an {@link Option} object's value was accessed
 * but its value was not set
 *
 * @author Pascal Weisenburger
 */
public class OptionNotSetException extends UnsupportedOperationException {
	private static final long serialVersionUID = 5250629400497623675L;

	public OptionNotSetException() {
		super("No value set");
	}

	public OptionNotSetException(String message) {
		super(message);
	}

	public OptionNotSetException(String message, Throwable cause) {
		super(message, cause);
	}
}
