package buisness;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import data.TrustCertificate;
import data.TrustAssessment;
import data.TrustView;

import util.Option;
import util.ValidationResult;

import CertainTrust.CertainTrust;

public class TrustComputation {
	private final TrustView trustView;

	public TrustComputation(TrustView trustView) {
		this.trustView = trustView;
	}

	private void updateAssessment(TrustCertificate S, boolean isLegitimateRoot) {
		// determine k and ca
		PublicKey k = S.getPublicKey();
		Principal ca = S.getSubject();

		if (trustView.hasTrustAssessment(k, ca))
			return;

		// determine o_kl
		Option<CertainTrust> o_kl = isLegitimateRoot
				? new Option<CertainTrust>(new CertainTrust(1.0, 1.0, 1.0, 1))
				: new Option<CertainTrust>();

		// determine o_it
		int n = 0;
		double f = 0.0;
		for (TrustAssessment assessment : trustView.getAssessments())
			for (TrustCertificate S_i : assessment.getS())
				if (S_i.getIssuer().equals(S.getIssuer())) {
					f += assessment.getO_it().getExpectation();
					n++;
					break;
				}
		CertainTrust o_it = new CertainTrust(0.5, 0.0, n == 0 ? 0.5 : f / n, 1);

		trustView.setAssessment(new TrustAssessment(k, ca, S, o_kl, o_it));
	}

	//TODO: VS: validation services need to implemented, just a placeholder input
	public ValidationResult validate(CertPath p, double l, double rc,
			Iterable<Object> VS) {
		Set<TrustCertificate> trustedCertificates =
				new HashSet<TrustCertificate>(trustView.getTrustedCertificates());
		Set<TrustCertificate> untrustedCertificates =
				new HashSet<TrustCertificate>(trustView.getUntrustedCertificates());

		List<? extends Certificate> certs = p.getCertificates();
		List<TrustCertificate> path = new ArrayList<>(certs.size());
		for (Certificate cert : certs)
			path.add(TrustCertificate.fromCertificate(cert));

		// check if C_n is already trusted
		if (trustedCertificates.contains(path.get(path.size() - 1)))
			return ValidationResult.TRUSTED;

		// check if p contains untrusted certificate
		for (TrustCertificate cert : path)
			if (untrustedCertificates.contains(cert))
				return ValidationResult.UNTRUSTED;

		// update trust assessments
		for (int i = 0; i < path.size() - 1; i++)
			updateAssessment(path.get(i), i == 0);

		// determine h (maximum i which the key is legitimate for)
		int h = 0;
		for (int i = 0; i < path.size() - 1; i++) {
			TrustCertificate cert = path.get(i);
			TrustAssessment assessment = trustView.getAssessment(
					cert.getPublicKey(), cert.getSubject());
			CertainTrust o_it = assessment.getO_it();
			if (o_it.getT() == 1.0 && o_it.getC() == 1.0 && o_it.getF() == 1.0)
				h = i;
		}

		// compute o_kl for C_n
		CertainTrust o_kl = null;
		for (int i = h; i < path.size() - 1; i++) {
			TrustCertificate cert = path.get(i);
			TrustAssessment assessment = trustView.getAssessment(
					cert.getPublicKey(), cert.getSubject());
			CertainTrust o_it = assessment.getO_it();

			if (o_kl == null)
				o_kl = o_it;
			else
				o_kl.AND(o_it);
		}

		// compute the expectation
		double exp = o_kl.getExpectation();
		if (exp >= l)
			return ValidationResult.TRUSTED;
		if (exp < l && o_kl.getC() >= rc)
			return ValidationResult.UNTRUSTED;

		// query validation service
//		for (Object vs : VS) {
//			// TODO: query validation service and return consensus
//		}

		return ValidationResult.UNKNOWN;

		// TODO: before return in any case: Update View. (See Section 4.5 for details.)
	}

}
