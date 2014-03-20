package support;

import java.security.cert.Certificate;

import sslcheck.core.NotaryManager;
import sslcheck.core.TLSConnectionInfo;
import util.ValidationResult;

public final class Service {
	private Service() { }
	
	public static ValidationService getValidationService(final String host) {
		return new ValidationService() {
			@Override
			public ValidationResult query(final Certificate certificate) {
				try {
					TLSConnectionInfo info = new TLSConnectionInfo(
							host, new Certificate[] { certificate });
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
