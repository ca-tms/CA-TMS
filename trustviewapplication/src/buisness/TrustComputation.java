package buisness;

import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import util.Option;
import util.ValidationResult;
import CertainTrust.CertainTrust;
import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

public class TrustComputation {
	private final TrustView trustView;

	// TODO: parameters should be configurable and globally accessible
	//       (maybe stored in the database)
//	public static final double lmin = 0.6;
//	public static final double lmed = 0.8;
//	public static final double lmax = 0.95;
	public static final double maxF = 0.8;
	public static final int opinionN = 10;
//	public static final int fixkl = 3;

	public TrustComputation(TrustView trustView) {
		this.trustView = trustView;
	}

	private TrustAssessment createAssessment(TrustCertificate S, boolean isLegitimateRoot) {
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
					0.5, 0.0, n == 0 ? 0.5 : Math.min(maxF, f_ca / n), opinionN);
			o_it_ee = new CertainTrust(
					0.5, 0.0, n == 0 ? 0.5 : Math.min(maxF, f_ee / n), opinionN);
		}

		return new TrustAssessment(k, ca, S, o_kl, o_it_ca, o_it_ee);
	}

	private void updateView(List<TrustCertificate> p, List<TrustAssessment> pAssessments,
			ValidationResult R, List<TrustAssessment> TL) {
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
					trustView.setAssessment(assessment);
			}

			trustView.setTrustedCertificate(p.get(p.size() - 1));
		}

		if (R == ValidationResult.UNTRUSTED) {
			// determine h (maximum i which is not a new assessment)
			//             (TODO: or the consensus is trusted)
			int h = 0;
			for (int i = 0; i < p.size() - 1; i++)
				if (!TL.contains(pAssessments.get(i)))
					h = i;

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
				if (nextAssessment != null &&
						(TL.contains(nextAssessment) ||
						 !nextAssessment.getS().contains(p.get(i + 1)))) {
					assessment.getO_it_ca().addR(1);
					updateTrustView = true;
				}

				// if assessment is in TL, add assessment to the view
				else if (TL.contains(assessment))
					updateTrustView = true;

				if (updateTrustView)
					trustView.setAssessment(assessment);
			}

			boolean updateTrustView = false;
			TrustAssessment assessment = pAssessments.get(h);

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
				trustView.setAssessment(assessment);

			// add C at position h+1 as untrusted certificate
			trustView.setUntrustedCertificate(p.get(h + 1));
		}
	}

	public ValidationResult validate(CertPath p, double l,
			Iterable<Object> VS) {
		List<? extends Certificate> certs = p.getCertificates();
		List<TrustCertificate> path = new ArrayList<>(certs.size());
		for (Certificate cert : certs)
			path.add(new TrustCertificate(cert));
		return validate(path, l, VS);
	}

	//TODO: VS: validation services need to implemented, just a placeholder input
	public ValidationResult validate(List<TrustCertificate> p, double l,
			Iterable<Object> VS) {
		Set<TrustCertificate> trustedCertificates =
				new HashSet<TrustCertificate>(trustView.getTrustedCertificates());
		Set<TrustCertificate> untrustedCertificates =
				new HashSet<TrustCertificate>(trustView.getUntrustedCertificates());

		// check if the last certificate is already trusted
		if (trustedCertificates.contains(p.get(p.size() - 1)))
			return ValidationResult.TRUSTED;

		// check if p contains untrusted certificate
		for (TrustCertificate cert : p)
			if (untrustedCertificates.contains(cert))
				return ValidationResult.UNTRUSTED;

		// update trust assessments
		List<TrustAssessment> TL = new ArrayList<>(p.size() - 1);
		List<TrustAssessment> pAssessments = new ArrayList<>(p.size() - 1);
		for (int i = 0; i < p.size() - 1; i++) {
			TrustAssessment assessment = trustView.getAssessment(p.get(i));
			if (assessment == null)
				TL.add(assessment = createAssessment(p.get(i), i == 0));
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
		if (exp < l && o_kl.getC() < 1) {
			// query validation service

			// TODO: query validation service and return consensus
			result = ValidationResult.UNKNOWN;
		}

		updateView(p, pAssessments, result, TL);
		return result;
	}
}
