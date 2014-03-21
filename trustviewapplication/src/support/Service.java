package support;

import java.security.cert.Certificate;

import data.TrustCertificate;

import sslcheck.core.NotaryManager;
import sslcheck.core.TLSConnectionInfo;
import util.ValidationResult;

public final class Service {
	private Service() { }

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
