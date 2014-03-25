package support;

import java.security.cert.Certificate;

import data.TrustCertificate;

import sslcheck.core.NotaryManager;
import sslcheck.core.TLSConnectionInfo;
import util.ValidationResult;

/**
 * Provides central access point for external services
 */
public final class Service {
	private Service() { }

	/**
	 * @return a {@link ValidationService} instance that can be used to query
	 * external validation services implemented as notaries
	 * @param host the host which validation is requested for
	 */
	public static ValidationService getValidationService(final String host) {
		return new ValidationService() {
			@Override
			public ValidationResult query(TrustCertificate certificate) {
				try {
					TLSConnectionInfo info = new TLSConnectionInfo(
							host, new Certificate[] { certificate.getCertificate() });
					NotaryManager nm = new NotaryManager();
					info.validateCertificates(nm);
					return info.isTrusted() ?
							ValidationResult.TRUSTED : ValidationResult.UNTRUSTED;
				}
				catch (Exception e) {
					e.printStackTrace();
					return ValidationResult.UNKNOWN;
				}
			}
		};
	}
}
