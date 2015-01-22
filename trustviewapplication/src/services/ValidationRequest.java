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
package services;

import java.util.Collections;
import java.util.List;

import util.CertificatePathValidity;
import data.TrustCertificate;

/**
 * Represents a validation query that was requested through a binding
 *
 * @author Pascal Weisenburger
 */
public class ValidationRequest {
	private final String url;
	private final List<TrustCertificate> certificatePath;
	private final double securityLevel;
	private final CertificatePathValidity certificatePathValidity;
	private final ValidationRequestSpec validationRequestSpec;

	/**
	 * Creates a new <code>ValidationRequest</code> instance
	 * @param url
	 * @param certifiactePath
	 * @param certificatePathValidity
	 * @param securityLevel
	 */
	public ValidationRequest(String url, List<TrustCertificate> certificatePath,
			CertificatePathValidity certificatePathValidity, double securityLevel,
			ValidationRequestSpec validationRequestSpec) {
		this.url = url;
		this.certificatePath = Collections.unmodifiableList(certificatePath);
		this.certificatePathValidity = certificatePathValidity;
		this.securityLevel = securityLevel;
		this.validationRequestSpec = validationRequestSpec;

		if (securityLevel < 0.0 || securityLevel > 1.0)
			throw new IllegalArgumentException(
				"Security level must have a value between 0 and 1, but was " + securityLevel);
	}

	/**
	 * @return the host URL which the validation was requested for
	 */
	public String getURL() {
		return url;
	}

	/**
	 * @return the certificate path which validation was requested for;
	 * the path starts with the self-signed root certificate and ends with the
	 * certificate for the end entity which validation was requested for
	 */
	public List<TrustCertificate> getCertificatePath() {
		return certificatePath;
	}

	/**
	 * @return the certificate validity as it was determined by the requesting client
	 */
	public CertificatePathValidity getCertificatePathValidity() {
		return certificatePathValidity;
	}

	/**
	 * @return the requested security level which is a value between 0 and 1
	 */
	public double getSecurityLevel() {
		return securityLevel;
	}

	/**
	 * @return the validation request specification
	 */
	public ValidationRequestSpec getValidationRequestSpec() {
		return validationRequestSpec;
	}
}
