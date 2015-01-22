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
package buisness;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import services.ValidationResultSpec;

import data.TrustCertificate;
import data.TrustView;

/**
 * Provides methods to control or retrieve information from the {@link TrustView}
 * 
 * @author Pascal Weisenburger
 */
public final class TrustViewControl {
	private TrustViewControl() { }

	private static Pattern subdomainPattern = Pattern.compile("^[^\\.]+\\.(.+\\..+)$");

	/**
	 * @return a host where the last sub domain is replaced by a wildcard "*"
	 * @param host
	 */
	private static String getWildcardHost(String host) {
		Matcher matcher = subdomainPattern.matcher(host);
		if (matcher.matches())
			return matcher.replaceFirst("*.$1");
		return null;
	}

	/**
	 * @return the host part from a URL
	 * @param hostURL
	 */
	private static String extractHost(String hostURL) {
		try {
			return new URL(hostURL).getHost();
		}
		catch (MalformedURLException e) {
			e.printStackTrace();
			return hostURL;
		}
	}

	/**
	 * Associates the given certificate with all hosts the certificate was
	 * issued for. Optionally, inserts an additional association to a host given
	 * by an URL. The existing associations can be retrieved by
	 * {@link #retrieveCertificatesForHost(TrustView, String)}.
	 * @see TrustCertificate#getSubjectHosts()
	 * @param trustView
	 * @param certificate
	 * @param hostURL
	 */
	public static void insertHostsForCertificate(TrustView trustView,
			TrustCertificate certificate, String hostURL) {
		Collection<String> certHosts = certificate.getSubjectHosts();
		for (String certHost : certHosts)
			trustView.addHostForCertificate(certificate, certHost);

		if (hostURL != null && !hostURL.isEmpty()) {
			String host = extractHost(hostURL);
			if (!certHosts.contains(host) && !certHosts.contains(getWildcardHost(host)))
				trustView.addHostForCertificate(certificate, host);
		}
	}

	/**
	 * @return the certificates that were associated with the given host. The
	 * associations were inserted using
	 * {@link #insertHostsForCertificate(TrustView, TrustCertificate, String)}
	 * @param trustView
	 * @param hostURL
	 */
	public static Collection<TrustCertificate> retrieveCertificatesForHost(
			TrustView trustView, String hostURL) {
		String host = extractHost(hostURL);
		Collection<TrustCertificate> certificates =
				trustView.getCertificatesForHost(host);

		if ((host = getWildcardHost(host)) != null)
			certificates.addAll(trustView.getCertificatesForHost(host));

		return certificates;
	}

	/**
	 * @return whether the given certificate is valid, i.e. neither expired nor
	 * revoked
	 * @param certificate
	 */
	public static boolean isCertificateValid(TrustView trustView,
			TrustCertificate certificate) {
		return !isCertificateExpired(certificate) &&
		       !isCertificateRevoked(trustView, certificate);
	}

	/**
	 * @return whether the given certificate is expired (or has not entered its
	 * validity period yet); does not check if the certificate is revoked
	 * @param certificate
	 */
	public static boolean isCertificateExpired(TrustCertificate certificate) {
		Date now = new Date();
		return
			certificate.getNotAfter().compareTo(now) < 0 ||
			certificate.getNotBefore().compareTo(now) > 0;
	}

	/**
	 * @return whether the given certificate is revoked; does not check if the
	 * certificate is outside of its validity period
	 * @param certificate
	 * @param trustView
	 */
	public static boolean isCertificateRevoked(TrustView trustView,
			TrustCertificate certificate) {
		return trustView.isCertificateRevoked(certificate);
	}

	/**
	 * @return the {@link ValidationResultSpec} for the given certificate and
	 * the given URL based on the information currently available in the
	 * {@link TrustView}
	 * @param trustView
	 * @param hostCertificate
	 * @param hostURL
	 */
	public static ValidationResultSpec deriveValidationSpec(
			TrustView trustView, Certificate hostCertificate, String hostURL) {
		return deriveValidationSpec(trustView,
				new TrustCertificate(hostCertificate), hostURL);
	}

	/**
	 * @return the {@link ValidationResultSpec} for the given certificate and
	 * the given URL based on the information currently available in the
	 * {@link TrustView}
	 * @param trustView
	 * @param hostCertificate
	 * @param hostURL
	 */
	public static ValidationResultSpec deriveValidationSpec(
			TrustView trustView, TrustCertificate hostCertificate, String hostURL) {
		if (trustView.isCertificateTrusted(hostCertificate) ||
				trustView.isCertificateUntrusted(hostCertificate))
			return ValidationResultSpec.VALIDATED;

		Collection<TrustCertificate> existingCertificates =
				retrieveCertificatesForHost(trustView, hostURL);

		Iterator<TrustCertificate> iterator = existingCertificates.iterator();
		while (iterator.hasNext())
			if (!trustView.isCertificateTrusted(iterator.next()))
				iterator.remove();

		for (TrustCertificate cert : existingCertificates)
			if (isCertificateExpired(cert) && !isCertificateRevoked(trustView, cert) &&
					cert.getIssuer().equals(hostCertificate.getIssuer()) &&
					cert.getPublicKey().equals(hostCertificate.getPublicKey()))
				return ValidationResultSpec.VALIDATED_EXISTING_EXPIRED_SAME_CA_KEY;

		for (TrustCertificate cert : existingCertificates)
			if (isCertificateValid(trustView, cert) &&
					!cert.getIssuer().equals(hostCertificate.getIssuer()) &&
					cert.getPublicKey().equals(hostCertificate.getPublicKey()))
				return ValidationResultSpec.VALIDATED_EXISTING_VALID_SAME_KEY;

		for (TrustCertificate cert : existingCertificates)
			if (!isCertificateValid(trustView, cert) &&
					cert.getIssuer().equals(hostCertificate.getIssuer()))
				return ValidationResultSpec.VALIDATED_EXISTING_EXPIRED_SAME_CA;

		for (TrustCertificate cert : existingCertificates)
			if (isCertificateValid(trustView, cert) &&
					cert.getIssuer().equals(hostCertificate.getIssuer()))
				return ValidationResultSpec.VALIDATED_EXISTING_VALID_SAME_CA;

		for (TrustCertificate cert : existingCertificates)
			if (!cert.getIssuer().equals(hostCertificate.getIssuer()) &&
					!cert.getPublicKey().equals(hostCertificate.getPublicKey()))
				return ValidationResultSpec.VALIDATED_EXISTING;

		return ValidationResultSpec.VALIDATED_FIRST_SEEN;
	}
}
