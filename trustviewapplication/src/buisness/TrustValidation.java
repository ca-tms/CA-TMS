package buisness;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import services.ValidationInformation;
import services.ValidationRequest;
import services.ValidationRequestSpec;
import services.ValidationResult;
import services.ValidationResultSpec;
import support.Service;
import support.ValidationService;
import data.Configuration;
import data.TrustCertificate;
import data.TrustView;

/**
 * <p>Implements the "Trust Validation Request Processing Algorithm" that
 * computes the a trust valuation based on the information currently contained
 * in the {@link TrustView} and the "Trust computation and validation" provided
 * by {@link TrustComputation}.</p>
 *
 * <p>The validation may incorporate the assessments of external
 * {@link ValidationService} for valuations or recommendations.</p>
 */
public final class TrustValidation {
	private TrustValidation() { }

	/**
	 * @return the validation result for the given argument; does not check
	 * if the certificate path is valid
	 * @param trustView the Trust View to be used
	 * @param config the configuration to be used
	 * @param validationService an external validation service
	 * @param request the trust validation request
	 */
	public static ValidationInformation validate(
			TrustView trustView, Configuration config,
			ValidationRequest request, ValidationService validationService) {
		String hostURL = request.getURL();
		List<TrustCertificate> certificatePath = request.getCertificatePath();
		double securityLevel = request.getSecurityLevel();
		ValidationRequestSpec spec = request.getValidationRequestSpec();

		final ValidationService defaultValidationService = validationService;
		final TrustCertificate hostCertificate =
				certificatePath.get(certificatePath.size() - 1);
		final long watchlistExpirationMillis =
				config.get(Configuration.WATCHLIST_EXPIRATION_MILLIS, Long.class);

		if (spec == ValidationRequestSpec.VALIDATE) {
			boolean bootstrappingMode =
					config.get(Configuration.BOOTSTRAPPING_MODE, Boolean.class);

			if (bootstrappingMode)
				spec = ValidationRequestSpec.VALIDATE_WITH_SERVICES;
			else
				spec = ValidationRequestSpec.VALIDATE_WITHOUT_SERVICES;
		}

		switch (spec) {
		case VALIDATE:
			// this never happens
			assert false;
			break;

		case RETRIEVE_RECOMMENDATION:
		case VALIDATE_WITH_SERVICES:
			// just use the default external validation service
			break;

		case VALIDATE_WITHOUT_SERVICES:
			// if we are should not use validation services, let the
			// validation services always return "unknown"
			// In case the existent information does neither provide a
			// trusted nor an untrusted validation result, the overall
			// result will be "unknown" and no experiences will be collected
			validationService =
				Service.getValidationService(ValidationResult.UNKNOWN);
			break;

		case VALIDATE_TRUST_END_CERTIFICATE:
			// if the user trusts the host certificate directly,
			// we will not run whole trust validation algorithm,
			// but just add the certificate to the watchlist
			trustView.addCertificateToWatchlist(hostCertificate);
			return new ValidationInformation(
					ValidationResult.TRUSTED,
					ValidationResultSpec.VALIDATED_ON_WATCHLIST);
		}

		if (spec == ValidationRequestSpec.RETRIEVE_RECOMMENDATION)
			return new ValidationInformation(
					validationService.query(hostCertificate),
					ValidationResultSpec.RECOMMENDED);

		assert
			spec == ValidationRequestSpec.VALIDATE_WITH_SERVICES ||
			spec == ValidationRequestSpec.VALIDATE_WITHOUT_SERVICES;

		// check if certificate is on the watchlist
		if (trustView.isCertificateOnWatchlist(hostCertificate)) {
			Date now = new Date();
			Date timestamp = trustView.getWatchlistCerrtificateTimestamp(
					hostCertificate);
			if (now.getTime() - timestamp.getTime() >
					watchlistExpirationMillis) {
				// certificate on watchlist has expired
				// the certificate must be checked
				// just proceed with the algorithm and use validation services
				validationService = defaultValidationService;
				trustView.removeCertificateFromWatchlist(hostCertificate);
			}
			else
				// certificate on watchlist has not expired yet
				// as long as the certificate is on the watchlist,
				// assume it is trusted
				return new ValidationInformation(
						ValidationResult.TRUSTED,
						ValidationResultSpec.VALIDATED_ON_WATCHLIST);
		}

		// determine result specification
		ValidationResultSpec resultSpec = TrustViewControl.deriveValidationSpec(
				trustView,
				certificatePath.get(certificatePath.size() - 1),
				hostURL);

		// trust certificate directly if it is issued for the same key
		// by the same CA as a previously trusted certificate
		if (resultSpec == ValidationResultSpec.VALIDATED_EXISTING_EXPIRED_SAME_CA_KEY) {
			validationService = Service.getValidationService(
					Collections.singletonList(hostCertificate), null,
					validationService);
		}

		// validate certificate path
		ValidationResult result = TrustComputation.validate(
				trustView, config,
				certificatePath,
				securityLevel,
				validationService);

		// update trust view host information
		if (result != ValidationResult.UNKNOWN)
			TrustViewControl.insertHostsForCertificate(
					trustView, hostCertificate, hostURL);

		// put certificate on watchlist if it was not validated trusted,
		// but is probably a normal certificate or CA change
		if (result == ValidationResult.UNKNOWN &&
				(resultSpec == ValidationResultSpec.VALIDATED_EXISTING_VALID_SAME_KEY ||
					resultSpec == ValidationResultSpec.VALIDATED_EXISTING_EXPIRED_SAME_CA)) {
			trustView.addCertificateToWatchlist(hostCertificate);
			return new ValidationInformation(
					ValidationResult.TRUSTED,
					ValidationResultSpec.VALIDATED_ON_WATCHLIST);
		}

		return new ValidationInformation(result, resultSpec);
	}

}
