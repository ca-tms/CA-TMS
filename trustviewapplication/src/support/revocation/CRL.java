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
package support.revocation;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import util.Option;

import data.TrustCertificate;

/**
 * Represents a Certificate Revocation List
 *
 * @author Pascal Weisenburger
 */
public class CRL {
	private X509CRL crl;
	private X509Certificate issuerCertificate;

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * retrieved from the given URL and is issued by the issuer which the given
	 * certificate is issued for
	 * @param url
	 * @param issuerCertificate
	 * @throws IOException if the CRL cannot be read
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(String url, TrustCertificate issuerCertificate)
			throws IOException, GeneralSecurityException {
		this(url, issuerCertificate.getCertificate(), -1);
	}

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * retrieved from the given URL and is issued by the issuer which the given
	 * certificate is issued for
	 * @param url
	 * @param issuerCertificate
	 * @throws IOException if the CRL cannot be read
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(String url, Certificate issuerCertificate)
			throws IOException, GeneralSecurityException {
		this(url, issuerCertificate, -1);
	}

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * retrieved from the given URL and is issued by the issuer which the given
	 * certificate is issued for; uses the given timeout for the download
	 * @param url
	 * @param issuerCertificate
	 * @param timeoutMillis
	 * @throws IOException if the CRL cannot be read
	 * @throws SocketTimeoutException if the connection times out
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(String url, TrustCertificate issuerCertificate, int timeoutMillis)
			throws IOException, GeneralSecurityException {
		this(url, issuerCertificate.getCertificate(), timeoutMillis);
	}

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * retrieved from the given URL and is issued by the issuer which the given
	 * certificate is issued for; uses the given timeout for the download
	 * @param url
	 * @param issuerCertificate
	 * @param timeoutMillis
	 * @throws IOException if the CRL cannot be read
	 * @throws SocketTimeoutException if the connection times out
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(String url, Certificate issuerCertificate, int timeoutMillis)
			throws IOException, GeneralSecurityException {
		if (url.startsWith("ldap://")) {
			Hashtable<String, String> environment = new Hashtable<>();
			environment.put(Context.INITIAL_CONTEXT_FACTORY,
					"com.sun.jndi.ldap.LdapCtxFactory");
			environment.put(Context.PROVIDER_URL, url);

			if (timeoutMillis >= 0) {
				String timeout = String.valueOf(timeoutMillis);
				environment.put("com.sun.jndi.ldap.connect.timeout", timeout);
				environment.put("com.sun.jndi.ldap.read.timeout", timeout);
			}

			try {
				DirContext context = new InitialDirContext(environment);
				byte[] value = (byte[]) context
						.getAttributes("")
						.get("certificateRevocationList;binary")
						.get();
				try (InputStream stream = new ByteArrayInputStream(value)) {
					initialize(stream, issuerCertificate);
				}
			}
			catch (NamingException | ClassCastException | NullPointerException e) {
				throw new IOException("Cannot download CRL from: " + url, e);
			}
		}
		else {
			URLConnection connection = new URL(url).openConnection();
			if (timeoutMillis >= 0) {
				connection.setConnectTimeout(timeoutMillis);
				connection.setReadTimeout(timeoutMillis);
			}
			try (InputStream stream = connection.getInputStream();
			     BufferedInputStream bufferedStream = new BufferedInputStream(stream)) {
				initialize(bufferedStream, issuerCertificate);
			}
		}
	}

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * read from the given stream and is issued by the issuer which the given
	 * certificate is issued for
	 * @param stream
	 * @param issuerCertificate
	 * @throws IOException if the CRL cannot be read
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(InputStream stream, TrustCertificate issuerCertificate)
			throws IOException, GeneralSecurityException {
		this(stream, issuerCertificate.getCertificate());
	}

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * read from the given stream and is issued by the issuer which the given
	 * certificate is issued for
	 * @param stream
	 * @param issuerCertificate
	 * @throws IOException if the CRL cannot be read
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(InputStream stream, Certificate issuerCertificate)
			throws IOException, GeneralSecurityException {
		initialize(stream, issuerCertificate);
	}

	/**
	 * Initializes the <code>CRL</code> instance based on the CRL that can be
	 * read from the given stream and is issued by the issuer which the given
	 * certificate is issued for
	 * @param stream
	 * @param issuerCertificate
	 * @throws IOException if the CRL cannot be read
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	private void initialize(InputStream stream, Certificate issuerCertificate)
			throws IOException, GeneralSecurityException {
		if (issuerCertificate instanceof X509Certificate)
			this.issuerCertificate = (X509Certificate) issuerCertificate;
		else
			throw new IllegalArgumentException("given certificate is no X.509 certificate");

		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		this.crl = (X509CRL) factory.generateCRL(stream);

		if (!verifyCRLSignature(this.crl, this.issuerCertificate))
			throw new SignatureException("CRL signature verification failed");
	}

	/**
	 * @return the next update date for the CRL
	 */
	public Option<Date> getNextUpdate() {
		return new Option<>(crl.getNextUpdate());
	}

	/**
	 * @return whether the given certificate has been revoked
	 * @param certificate
	 */
	public boolean isRevoked(TrustCertificate certificate) {
		if (certificate.getCertificate() != null)
			return isRevoked(certificate.getCertificate());
		return true;
	}

	/**
	 * @return whether the given certificate has been revoked
	 * @param certificate
	 */
	public boolean isRevoked(Certificate certificate) {
		return crl.isRevoked(certificate);
	}

	/**
	 * @return the underlying {@link java.security.cert.CRL} object
	 */
	public java.security.cert.CRL getCRL() {
		return crl;
	}

	/**
	 * @return whether the given CRL can be verified using the given issuer
	 * certificate
	 * @param crl
	 * @param issuerCertificate
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	private static boolean verifyCRLSignature(X509CRL crl,
			X509Certificate issuerCertificate)
					throws GeneralSecurityException, IOException {
		if (crl == null)
			return false;

		Signature signature = Signature.getInstance(crl.getSigAlgName());

		if (crl.getSigAlgParams() != null) {
			AlgorithmParameters params =
					AlgorithmParameters.getInstance(crl.getSigAlgName());
			params.init(crl.getSigAlgParams());

			signature.setParameter(
					params.getParameterSpec(AlgorithmParameterSpec.class));
		}

		signature.initVerify(issuerCertificate.getPublicKey());
		signature.update(crl.getTBSCertList());
		return signature.verify(crl.getSignature());
	}
}
