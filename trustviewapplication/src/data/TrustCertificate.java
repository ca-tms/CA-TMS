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

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

/**
 * Represents a certificate as used by the CA Trust Management System
 * abstracting over the underlying {@link Certificate} implementation
 * (which has to be {@link X509Certificate})
 * 
 * @author Pascal Weisenburger
 */
public class TrustCertificate {
	private final String serial;
	private final String issuer;
	private final String subject;
	private final String publicKey;
	private final Date notBefore;
	private final Date notAfter;
	private final X509Certificate certificate;
	private List<String> subjectHosts;

	/**
	 * Creates a new <code>Certificate</code> initializing it with all data that
	 * is needed for a certificate in the CA Trust Management System
	 */
	public TrustCertificate(String serial, String issuer, String subject,
			String publicKey, Date notBefore, Date notAfter) {
		this.serial = serial;
		this.issuer = issuer;
		this.subject = subject;
		this.publicKey = publicKey;
		this.notBefore = notBefore;
		this.notAfter = notAfter;
		this.certificate = null;
	}

	/**
	 * Creates a new <code>Certificate</code> initializing it with all data that
	 * is needed for a certificate in the CA Trust Management System
	 * based on the given {@link Certificate} instance which can later be
	 * accessed using {@link #getCertificate()}
	 */
	public TrustCertificate(Certificate certificate) {
		if (certificate instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) certificate;

			this.serial = x509cert.getSerialNumber().toString();
			this.issuer = x509cert.getIssuerX500Principal().getName(
					X500Principal.CANONICAL);
			this.subject = x509cert.getSubjectX500Principal().getName(
					X500Principal.CANONICAL);
			this.publicKey = DatatypeConverter.printBase64Binary(
					x509cert.getPublicKey().getEncoded());
			this.notBefore = x509cert.getNotBefore();
			this.notAfter = x509cert.getNotAfter();
			this.certificate = x509cert;
		}
		else
			throw new UnsupportedOperationException(
					"Cannot create a TrustCertificate from a " +
					certificate.getClass().getSimpleName());
	}

	/**
	 * @return the certificate serial number
	 */
	public String getSerial() {
		return serial;
	}

	/**
	 * @return the certificate issuer
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * @return the certificate subject
	 */
	public String getSubject() {
		return subject;
	}

	/**
	 * @return the encoded certificate public key
	 */
	public String getPublicKey() {
		return publicKey;
	}

	/**
	 * @return the date which before the certificate is not valid
	 */
	public Date getNotBefore() {
		return notBefore;
	}

	/**
	 * @return the date which after the certificate is not valid
	 */
	public Date getNotAfter() {
		return notAfter;
	}

	/**
	 * @return the underlying {@link Certificate} implementation;
	 * will return <code>null</code> if the <code>TrustCertificate</code>
	 * instance was not created using the {@link #TrustCertificate(Certificate)}
	 * constructor
	 */
	public Certificate getCertificate() {
		return certificate;
	}

	/**
	 * @return the subject common names of the underlying {@link Certificate}
	 * implementation; will return <code>null</code> if the
	 * <code>TrustCertificate</code> instance was not created using the
	 * {@link #TrustCertificate(Certificate)} constructor
	 */
	public List<String> getSubjectHosts() {
		if (certificate == null)
			return null;

		if (subjectHosts != null)
			return subjectHosts;

		subjectHosts = new ArrayList<>();
		try {
			Collection<List<?>> names = certificate.getSubjectAlternativeNames();
			if (names != null) {
				// extract "DNS Name" values from subject alternative names
				for (List<?> name : names)
					if ((Integer) name.get(0) == 2)
						subjectHosts.add((String) name.get(1));
			}
			else {
				String name = certificate.getSubjectX500Principal().getName();
				for (String component : name.split(",")) {
					component = component.trim();
					if (component.substring(0, 3).toLowerCase().equals("cn=")) {
						String cn = component.substring(3);
						if (cn.matches(
								"^(\\*\\.)?" +
								"(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)+" +
								"(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.?)$"))
							subjectHosts.add(cn);
						break;
					}
				}
			}
		}
		catch (CertificateParsingException e) {
			e.printStackTrace();
		}

		return subjectHosts;
	}

	@Override
	public int hashCode() {
		return 29791 * serial.hashCode() + 961 * issuer.hashCode() +
		       31 * subject.hashCode() + publicKey.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		TrustCertificate other = (TrustCertificate) obj;
		return serial.equals(other.getSerial()) &&
		       issuer.equals(other.getIssuer()) &&
		       subject.equals(other.getSubject()) &&
		       publicKey.equals(other.getPublicKey());
	}
}
