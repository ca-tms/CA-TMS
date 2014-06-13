package buisness;

import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import support.ValidationService;
import util.Option;
import util.ValidationResult;
import CertainTrust.CertainTrust;
import data.Configuration;
import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

/**
 * <p>Implements the Trust computation and validation as described in
 * <q>Trust views for the web pki</q> [1], sections 4.3, 4.4 and 4.5.</p>
 *
 * <p>[1] Johannes Braun, Florian Volk, Johannes Buchmann, and Max Mühlhäuser.
 * Trust views for the web pki. 2013.</p>
 */
public final class TrustComputation {
	private TrustComputation() { }

	/**
	 * Implements the initialization of Trust Assessments as described in
	 * <q>Trust views for the web pki</q> [1], section 4.3
	 *
	 * @param trustView the Trust View to be used
	 * @param config the configuration to be used
	 * @param S the certificate that certifies the entity
	 *          which the Trust Assessment should be initialized for
	 * @param isLegitimateRoot <code>true</code> if the entity is a root entity
	 * @return the initialized Trust Assessment
	 */
	private static TrustAssessment createAssessment(
			TrustView trustView, Configuration config,
			TrustCertificate S, boolean isLegitimateRoot) {
		final int opinionN = config.get(Configuration.OPINION_N, Integer.class);
		final double opinionMaxF = config.get(Configuration.OPINION_MAX_F, Double.class);

		// determine k and ca
		String k = S.getPublicKey();
		String ca = S.getSubject();

		// determine o_kl
		Option<CertainTrust> o_kl = isLegitimateRoot
				? new Option<CertainTrust>(new CertainTrust(1.0, 1.0, 1.0, opinionN))
				: new Option<CertainTrust>();

		// determine o_it
		Collection<TrustAssessment> assessments = trustView.getAssessments();
		CertainTrust o_it_ca = null, o_it_ee = null;

		for (TrustAssessment assessment : assessments)
			if (assessment.getCa().equals(ca)) {
				o_it_ca = assessment.getO_it_ca();
				o_it_ee = assessment.getO_it_ee();
				break;
			}

		if (o_it_ca == null || o_it_ee == null) {
			int n = 0;
			double f_ca = 0.0, f_ee = 0.0;
			for (TrustAssessment assessment : assessments)
				for (TrustCertificate S_i : assessment.getS())
					if (S_i.getIssuer().equals(S.getIssuer())) {
						f_ca += assessment.getO_it_ca().getExpectation();
						f_ee += assessment.getO_it_ee().getExpectation();
						n++;
						break;
					}

			o_it_ca = new CertainTrust(
					0.5, 0.0, n == 0 ? 0.5 : Math.min(opinionMaxF, f_ca / n), opinionN);
			o_it_ee = new CertainTrust(
					0.5, 0.0, n == 0 ? 0.5 : Math.min(opinionMaxF, f_ee / n), opinionN);
		}

		return new TrustAssessment(k, ca, S, o_kl, o_it_ca, o_it_ee);
	}

	/**
	 * Implements the Trust View update as described in
	 * <q>Trust views for the web pki</q> [1], section 4.5
	 *
	 * @param trustView the Trust View to be used
	 * @param config the configuration to be used
	 * @param p a certificate path
	 * @param pAssessments the assessments belonging to the certificates in the
	 *                     certificate path <code>p</code> at the corresponding index
	 * @param R the result of the trust validation
	 * @param TL the list of new Trust Assessments
	 * @param VS an external validation service
	 */
	private static void updateView(TrustView trustView, Configuration config,
			List<TrustCertificate> p, List<TrustAssessment> pAssessments,
			ValidationResult R, List<TrustAssessment> TL, ValidationService VS) {
		final int opinionN = config.get(Configuration.OPINION_N, Integer.class);
		final double fix_kl = config.get(Configuration.FIX_KL, Double.class);

		if (R == ValidationResult.TRUSTED) {
			for (int i = 0; i < p.size() - 1; i++) {
				boolean updateTrustView = false;
				TrustAssessment assessment = pAssessments.get(i);
				TrustAssessment nextAssessment = i + 1 < pAssessments.size()
						? pAssessments.get(i + 1) : null;

				// if C is not in S, add C to S
				if (!assessment.getS().contains(p.get(i))) {
					assessment.getS().add(p.get(i));
					updateTrustView = true;
				}

				// if this is the second last certificate in the chain
				// or the next assessment is in TL
				// or the next C is not in the next S
				// for the next trust assessment
				// update the current assessment with a positive experience
				if (i == p.size() - 2) {
					assessment.getO_it_ee().addR(1);
					updateTrustView = true;
				}
				else if (nextAssessment != null &&
							(TL.contains(nextAssessment) ||
								!nextAssessment.getS().contains(p.get(i + 1)))) {
					assessment.getO_it_ca().addR(1);
					updateTrustView = true;
				}

				// if assessment is in TL, add assessment to the view
				else if (TL.contains(assessment))
					updateTrustView = true;

				if (updateTrustView)
					trustView.setAssessment(
							fixKeyLegitimacy(opinionN, fix_kl, assessment));
			}

			trustView.setTrustedCertificate(p.get(p.size() - 1));
		}

		if (R == ValidationResult.UNTRUSTED) {
			final boolean queryServicesForCaCerts =
					config.get(Configuration.QUERY_SERVICES_FOR_CA_CERTS, Boolean.class);

			int h = 0;
			if (queryServicesForCaCerts) {
				// determine h
				// maximum i which is not a new assessment or
				// which the validation service consensus is trusted for
				for (int i = 0; i < p.size() - 1; i++)
					if (!TL.contains(pAssessments.get(i)))
						h = i;
				for (int i = h; i < p.size() - 1; i++)
					if (VS.query(p.get(i)) == ValidationResult.TRUSTED)
						h = i;
			}
			else
				// make sure the end entity certificate is marked untrusted
				// and the CA assessment is updated with a negative experience
				// do not update any other assessments
				h = p.size() - 2;

			for (int i = 0; i < h; i++) {
				boolean updateTrustView = false;
				TrustAssessment assessment = pAssessments.get(i);
				TrustAssessment nextAssessment = i + 1 < pAssessments.size()
						? pAssessments.get(i + 1) : null;

				// if C is not in S, add C to S
				if (!assessment.getS().contains(p.get(i))) {
					assessment.getS().add(p.get(i));
					updateTrustView = true;
				}

				// if the next assessment is in TL
				// or the next C is not in the next S,
				// update the current assessment with a positive experience
				if (queryServicesForCaCerts &&
						nextAssessment != null &&
						(TL.contains(nextAssessment) ||
						 !nextAssessment.getS().contains(p.get(i + 1)))) {
					assessment.getO_it_ca().addR(1);
					updateTrustView = true;
				}

				// if assessment is in TL, add assessment to the view
				else if (TL.contains(assessment))
					updateTrustView = true;

				if (updateTrustView)
					trustView. setAssessment(
							fixKeyLegitimacy(opinionN, fix_kl, assessment));
			}

			boolean updateTrustView = false;
			TrustAssessment assessment = pAssessments.get(h);

			if (queryServicesForCaCerts) {
				// if C at position h is not in S at position h,
				// add it to the set
				if (!assessment.getS().contains(p.get(h))) {
					assessment.getS().add(p.get(h));
					updateTrustView = true;
				}

				// if assessment at position h is in TL,
				// add the assessment to the view
				if (TL.contains(assessment))
					updateTrustView = true;
			}

			// If C at position h+1 is not an untrusted certificate,
			// update the assessment with a negative experience
			if (!trustView.getUntrustedCertificates().contains(p.get(h + 1))) {
				if (h < p.size() - 2)
					assessment.getO_it_ca().addS(1);
				else
					assessment.getO_it_ee().addS(1);
				updateTrustView = true;
			}

			if (updateTrustView)
				trustView.setAssessment(
						fixKeyLegitimacy(opinionN, fix_kl, assessment));

			// add C at position h+1 as untrusted certificate
			trustView.setUntrustedCertificate(p.get(h + 1));
		}
	}

	private static void updateAssessmentsTimestamps(TrustView trustView, List<TrustCertificate> p) {
		for (int i = 0; i < p.size() - 1; i++)
			trustView.setAssessmentValid(
					p.get(i).getPublicKey(), p.get(i).getSubject());
	}

	private static TrustAssessment fixKeyLegitimacy(int opinionN, double fix_kl,
			TrustAssessment assessment) {
		if (assessment.getO_it_ca().getR() + assessment.getO_it_ee().getR() >= fix_kl)
			return new TrustAssessment(
					assessment.getK(), assessment.getCa(), assessment.getS(),
					new Option<>(new CertainTrust(1.0, 1.0, 1.0, opinionN)),
					assessment.getO_it_ca(), assessment.getO_it_ee());

		return assessment;
	}

	/**
	 * Implements the Trust Validation as described in
	 * <q>Trust views for the web pki</q> [1], section 4.4
	 *
	 * @param trustView the Trust View to be used
	 * @param config the configuration to be used
	 * @param path a certificate path
	 *        (starting with he certificate for the end entity and ending with
	 *        the certificate issued by the root CA
	 *        excluding the self-signed certificate for the root CA itself
	 *        in compliance with the documentation for {@link CertPath})
	 * @param pathAnchor the self-signed root certificate
	 * @param l the security level (between 0 and 1) to be used
	 * @param VS an external validation service
	 * @return the result of the trust validation
	 */
	public static ValidationResult validate(TrustView trustView, Configuration config,
			CertPath path, Certificate pathAnchor, double l, ValidationService VS) {
		List<? extends Certificate> certs = path.getCertificates();
		List<TrustCertificate> p = new ArrayList<>(
				Collections.<TrustCertificate>nCopies(certs.size() + 1, null));

		int i = certs.size();
		for (Certificate cert : certs)
			p.set(i--, new TrustCertificate(cert));
		p.set(0, new TrustCertificate(pathAnchor));

		return validate(trustView, config, p, l, VS);
	}

	/**
	 * Implements the Trust Validation as described in
	 * <q>Trust views for the web pki</q> [1], section 4.4
	 *
	 * @param trustView the Trust View to be used
	 * @param config the configuration to be used
	 * @param path a certificate path
	 *        (starting with the certificate for the end entity and ending with
	 *        the self-signed root certificate)
	 * @param pathAnchor the self-signed root certificate
	 * @param l the security level (between 0 and 1) to be used
	 * @param VS an external validation service
	 * @return the result of the trust validation
	 */
	public static ValidationResult validate(TrustView trustView, Configuration config,
			Certificate[] path, double l, ValidationService VS) {
		List<TrustCertificate> p = new ArrayList<>(
				Collections.<TrustCertificate>nCopies(path.length, null));

		int i = path.length - 1;
		for (Certificate cert : path)
			p.set(i--, new TrustCertificate(cert));

		return validate(trustView, config, p, l, VS);
	}

	/**
	 * Implements the Trust Validation as described in
	 * <q>Trust views for the web pki</q> [1], section 4.4
	 *
	 * @param trustView the Trust View to be used
	 * @param config the configuration to be used
	 * @param p a certificate path
	 *        (starting with the self-signed root certificate and ending with
	 *        the certificate for the end entity,
	 *        in compliance with the definition used in [1])
	 * @param l the security level (between 0 and 1) to be used
	 * @param VS an external validation service
	 * @return the result of the trust validation
	 */
	public static ValidationResult validate(TrustView trustView, Configuration config,
			List<TrustCertificate> p, double l, ValidationService VS) {
		Set<TrustCertificate> trustedCertificates =
				new HashSet<TrustCertificate>(trustView.getTrustedCertificates());
		Set<TrustCertificate> untrustedCertificates =
				new HashSet<TrustCertificate>(trustView.getUntrustedCertificates());

		// check if the last certificate is already trusted
		if (trustedCertificates.contains(p.get(p.size() - 1))) {
			updateAssessmentsTimestamps(trustView, p);
			return ValidationResult.TRUSTED;
		}

		// check if p contains untrusted certificate
		for (TrustCertificate cert : p)
			if (untrustedCertificates.contains(cert)) {
				updateAssessmentsTimestamps(trustView, p);
				return ValidationResult.UNTRUSTED;
			}

		// update trust assessments
		List<TrustAssessment> TL = new ArrayList<>(p.size() - 1);
		List<TrustAssessment> pAssessments = new ArrayList<>(p.size() - 1);
		for (int i = 0; i < p.size() - 1; i++) {
			TrustAssessment assessment = trustView.getAssessment(p.get(i));
			if (assessment == null) {
				assessment = createAssessment(trustView, config, p.get(i), i == 0);
				TL.add(assessment);
			}
			pAssessments.add(assessment);
		}

		// determine h (maximum i which the key is legitimate for)
		int h = 0;
		for (int i = 0; i < p.size() - 1; i++) {
			Option<CertainTrust> o_kl_opt = pAssessments.get(i).getO_kl();
			if (o_kl_opt.isSet()) {
				CertainTrust o_kl = o_kl_opt.get();
				if (o_kl.getT() == 1.0 && o_kl.getC() == 1.0 && o_kl.getF() == 1.0)
					h = i;
			}
		}

		// compute o_kl for last C
		CertainTrust o_kl = null;
		for (int i = h; i < p.size() - 1; i++) {
			TrustAssessment assessment = pAssessments.get(i);
			CertainTrust o_it = i < p.size() - 2
					? assessment.getO_it_ca()
				    : assessment.getO_it_ee();
			o_kl = o_kl == null ? o_it : o_kl.AND(o_it);
		}

		// compute the expectation
		ValidationResult result = ValidationResult.UNKNOWN;
		double exp = o_kl.getExpectation();
		if (exp >= l)
			result = ValidationResult.TRUSTED;
		if (exp < l && o_kl.getC() == 1)
			result = ValidationResult.UNTRUSTED;
		if (exp < l && o_kl.getC() < 1)
			// compute consensus of validation service
			result = VS.query(p.get(p.size() - 1));

		updateView(trustView, config, p, pAssessments, result, TL, VS);
		updateAssessmentsTimestamps(trustView, p);
		return result;
	}
}
