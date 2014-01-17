package data;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import util.Option;

import CertainTrust.CertainTrust;

public class TrustAssessment {
	// public key
	private final String k;

	// CA name
	private final String ca;

	// certificates for k
	private final Set<TrustCertificate> S;

	// opinion whether k belongs to ca (key legitimacy)
	private final Option<CertainTrust> o_kl;

	// opinion on the trust in ca to issue trustworthy certificates for CAs
	// (issuer trust in ca, when using k to sign CAs)
	private final CertainTrust o_it_ca;

	// opinion on the trust in ca to issue trustworthy certificates for end entities
	// (issuer trust in ca, when using k to sign end entities)
	private final CertainTrust o_it_ee;

	public TrustAssessment(String k, String ca, Set<TrustCertificate> S,
			Option<CertainTrust> o_kl, CertainTrust o_it_ca, CertainTrust o_it_ee) {
		this.k = k;
		this.ca = ca;
		this.S = S;
		this.o_kl = o_kl;
		this.o_it_ca = o_it_ca;
		this.o_it_ee = o_it_ee;
	}

	public TrustAssessment(String k, String ca, TrustCertificate S,
			Option<CertainTrust> o_kl, CertainTrust o_it_ca, CertainTrust o_it_ee) {
		this(k, ca, new HashSet<>(Collections.singleton(S)),
		     o_kl, o_it_ca, o_it_ee);
	}

	@Override
	public TrustAssessment clone() {
		return o_kl.isSet()
				? new TrustAssessment(
						k, ca, new HashSet<>(S),
						new Option<CertainTrust>(o_kl.get().clone()),
						o_it_ca.clone(), o_it_ee.clone())
				: new TrustAssessment(
						k, ca, new HashSet<>(S),
						new Option<CertainTrust>(),
						o_it_ca.clone(), o_it_ee.clone());
	}

	@Override
	public String toString() {
		String str = "";
		for (TrustCertificate s : S)
			str += str.isEmpty() ? s : ", " + s;
		str = "{" + str + "}, ";

		str += o_kl.isSet()
				? "(" + o_kl.get().getT() + ", " + o_kl.get().getC() + ", " +
				        o_kl.get().getF() + ")"
				: "unknown";

		return "(" + k + ", " + ca + ", " + str + ", (" +
		       o_it_ca.getT() + ", " + o_it_ca.getC() + ", " + o_it_ca.getF() + "), (" +
		       o_it_ee.getT() + ", " + o_it_ee.getC() + ", " + o_it_ee.getF() + "))";
	}

	public String getK() {
		return k;
	}

	public String getCa() {
		return ca;
	}

	public Set<TrustCertificate> getS() {
		return S;
	}

	public Option<CertainTrust> getO_kl() {
		return o_kl;
	}

	public CertainTrust getO_it_ca() {
		return o_it_ca;
	}

	public CertainTrust getO_it_ee() {
		return o_it_ee;
	}
}
