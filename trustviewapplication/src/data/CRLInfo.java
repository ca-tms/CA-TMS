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

import java.security.cert.CRL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import util.Option;

/**
 * Represents access information to Certificate Revocation Lists
 * 
 * @author Pascal Weisenburger
 */
public class CRLInfo {
	private final TrustCertificate crlIssuer;
	private final List<String> urls;
	private final Option<Date> nextUpdate;
	private final Option<CRL> crl;

	/**
	 * Creates a new <code>CRLInfo</code> instance
	 * @param crlIssuer the issuer of the CRL
	 * @param urls the URLs where the CRL can be retrieved from
	 * @param nextUpdate the next update date for the CRL if available
	 * @param crl the CRL data if available
	 */
	public CRLInfo(TrustCertificate crlIssuer, List<String> urls,
			Option<Date> nextUpdate, Option<? extends CRL> crl) {
		this.crlIssuer = crlIssuer;
		this.urls = Collections.unmodifiableList(new ArrayList<>(urls));
		this.nextUpdate = nextUpdate;
		this.crl = crl.isSet() ? new Option<CRL>(crl.get()) : new Option<CRL>();
	}

	/**
	 * Creates a new <code>CRLInfo</code> instance
	 * @param crlIssuer the issuer of the CRL
	 * @param urls the URLs where the CRL can be retrieved from
	 */
	public CRLInfo(TrustCertificate crlIssuer, List<String> urls) {
		this.crlIssuer = crlIssuer;
		this.urls = Collections.unmodifiableList(new ArrayList<>(urls));
		this.nextUpdate = new Option<>();
		this.crl = new Option<>();
	}
	/**
	 * @return the issuer of the CRL
	 */
	public TrustCertificate getCRLIssuer() {
		return crlIssuer;
	}

	/**
	 * @return the URLs where the CRL can be retrieved from
	 */
	public List<String> getURLs() {
		return urls;
	}

	/**
	 * @return the next update date for the CRL if available
	 */
	public Option<Date> getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * @return the CRL data if available
	 */
	public Option<CRL> getCRL() {
		return crl;
	}

	/**
	 * @return whether the given certificate has been revoked; will return
	 * <code>false</code> if the CRL data is not available
	 * @see #getCRL()
	 * @param certificate
	 */
	public boolean isRevoked(TrustCertificate certificate) {
		if (!crl.isSet())
			return false;
		if (certificate.getCertificate() == null)
			return true;
		return crl.get().isRevoked(certificate.getCertificate());
	}

	@Override
	public int hashCode() {
		return 31 * crlIssuer.hashCode() + urls.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		CRLInfo other = (CRLInfo) obj;
		return crlIssuer.equals(other.getCRLIssuer()) &&
		       urls.equals(other.getURLs());
	}
}
