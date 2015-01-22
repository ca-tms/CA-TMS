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
 * Indicates that accessing the data model failed
 * 
 * @author Pascal Weisenburger
 */
public class ModelAccessException extends Exception {
	private static final long serialVersionUID = -4988969206288878607L;

	public ModelAccessException(Throwable cause) {
		super("Error accessing the data model", cause);
	}

	public ModelAccessException() { }

	public ModelAccessException(String message) {
		super(message);
	}

	public ModelAccessException(String message, Throwable cause) {
		super(message, cause);
	}

	public ModelAccessException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}
}
