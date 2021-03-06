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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import util.Option;

/**
 * Represents access information to OCSP services for a certificate issuer
 * 
 * @author Pascal Weisenburger
 */
public class OCSPInfo {
	private final TrustCertificate certificateIssuer;
	private final List<String> urls;
	private final Option<Date> nextUpdate;

	/**
	 * Creates a new <code>OCSPInfo</code> instance
	 * @param certificateIssuer the issuer of the certificates to be checked
	 * @param urls the URLs where the OSCP services can be reached
	 * @param nextUpdate the next update date for the OCSP service if available
	 */
	public OCSPInfo(TrustCertificate certificateIssuer, List<String> urls,
			Option<Date> nextUpdate) {
		this.certificateIssuer = certificateIssuer;
		this.urls = Collections.unmodifiableList(new ArrayList<>(urls));
		this.nextUpdate = nextUpdate;
	}

	/**
	 * Creates a new <code>OCSPInfo</code> instance
	 * @param certificateIssuer the issuer of the certificates to be checked
	 * @param urls the URLs where the OSCP services can be reached
	 */
	public OCSPInfo(TrustCertificate certificateIssuer, List<String> urls) {
		this.certificateIssuer = certificateIssuer;
		this.urls = Collections.unmodifiableList(new ArrayList<>(urls));
		this.nextUpdate = new Option<>();
	}

	/**
	 * @return the issuer of the certificates to be checked
	 */
	public TrustCertificate getCertificateIssuer() {
		return certificateIssuer;
	}

	/**
	 * @return the URLs where the OSCP services can be reached
	 */
	public List<String> getURLs() {
		return urls;
	}

	/**
	 * @return the next update date for the OCSP service if available
	 */
	public Option<Date> getNextUpdate() {
		return nextUpdate;
	}

	@Override
	public int hashCode() {
		return 31 * certificateIssuer.hashCode() + urls.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		OCSPInfo other = (OCSPInfo) obj;
		return certificateIssuer.equals(other.getCertificateIssuer()) &&
		       urls.equals(other.getURLs());
	}
}
