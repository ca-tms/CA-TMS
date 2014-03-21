package support;

import data.TrustCertificate;

import util.ValidationResult;

public interface ValidationService {
	ValidationResult query(TrustCertificate certificate);
}
