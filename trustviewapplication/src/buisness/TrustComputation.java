package buisness;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertPath;

import data.TrustCertificate;
import data.TrustAssessment;
import data.TrustView;

import util.Option;

import CertainTrust.CertainTrust;

public class TrustComputation {
	private final TrustView trustView;

	public TrustComputation(TrustView trustView) {
		this.trustView = trustView;
	}

	public void updateAssessment(TrustCertificate S, boolean isKeyLegitimate) {
		// determine k and ca
		PublicKey k = S.getPublicKey();
		Principal ca = S.getSubject();

		if (trustView.hasTrustAssessment(k, ca))
			return;

		// determine o_kl
		Option<CertainTrust> o_kl = isKeyLegitimate
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

	public void processX509CertPath(CertPath path, boolean isLegitimateAnchor) {
		boolean firstCert = true;
		for (java.security.cert.Certificate cert : path.getCertificates()) {
			updateAssessment(
					TrustCertificate.fromCertificate(cert),
					firstCert && isLegitimateAnchor);
			firstCert = false;
		}
	}
}
