package services.logic;

import java.util.List;

import util.CertificatePathValidity;
import data.TrustCertificate;

public class ValidationRequest {
	private final String url;
	private final List<TrustCertificate> certifiactePath;
	private final double securityLevel;
	private final CertificatePathValidity certificatePathValidity;

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

	public String getURL() {
		return url;
	}

	public List<TrustCertificate> getCertifiactePath() {
		return certifiactePath;
	}

	public CertificatePathValidity getCertificatePathValidity() {
		return certificatePathValidity;
	}

	public double getsecurityLevel() {
		return securityLevel;
	}
}
