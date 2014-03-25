package services.logic;

import java.util.List;

import util.CertificatePathValidity;
import data.TrustCertificate;

/**
 * Represents a validation query that was requested through a binding
 */
public class ValidationRequest {
	private final String url;
	private final List<TrustCertificate> certifiactePath;
	private final double securityLevel;
	private final CertificatePathValidity certificatePathValidity;

	/**
	 * Creates a new <code>ValidationRequest</code> instance
	 * @param url
	 * @param certifiactePath
	 * @param certificatePathValidity
	 * @param securityLevel
	 */
	public ValidationRequest(String url, List<TrustCertificate> certifiactePath,
			CertificatePathValidity certificatePathValidity, double securityLevel) {
		this.url = url;
		this.certifiactePath = certifiactePath;
		this.certificatePathValidity = certificatePathValidity;
		this.securityLevel = securityLevel;

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
	public List<TrustCertificate> getCertifiactePath() {
		return certifiactePath;
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
	public double getsecurityLevel() {
		return securityLevel;
	}
}
