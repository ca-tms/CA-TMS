package support;

import java.security.cert.Certificate;

import util.ValidationResult;

public interface ValidationService {
	ValidationResult[] query(Certificate certificate);
}
