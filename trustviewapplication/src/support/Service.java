package support;

import java.net.MalformedURLException;
import java.security.cert.Certificate;

import sslcheck.core.NotaryManager;
import sslcheck.core.NotaryRating;
import sslcheck.core.NotaryRatingException;
import sslcheck.core.TLSCertificateException;
import sslcheck.core.TLSConnectionInfo;
import util.ValidationResult;

public final class Service {
	private Service() { }

	private static NotaryRating ratingObject = NotaryRating.getInstance();

	public static ValidationService getValidationService(final String host) {
		return new ValidationService() {
			@Override
			public ValidationResult query(final Certificate certificate) {
				synchronized (ratingObject) {
					try {
						TLSConnectionInfo info = new TLSConnectionInfo(
								host, new Certificate[] { certificate });
						NotaryManager nm = new NotaryManager();
						info.validateCertificates(nm);
						return ratingObject.isPossiblyTrusted() ?
								ValidationResult.TRUSTED : ValidationResult.UNTRUSTED;
					}
					catch (TLSCertificateException | NotaryRatingException | MalformedURLException e) {
						e.printStackTrace();
						return ValidationResult.UNKNOWN;
					}
					finally {
						ratingObject.clear();
					}
				}
			}
		};
	}
}
