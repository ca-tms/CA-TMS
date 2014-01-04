package data;

import java.security.Principal;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

import util.Option;

import CertainTrust.CertainTrust;

public class TrustAssessment {
	// public key
	private final PublicKey k;

	// CA name
	private final Principal ca;

	// certificates for k
	private final Set<TrustCertificate> S;

	// opinion whether k belongs to ca (key legitimacy)
	private final Option<CertainTrust> o_kl;

	// opinion on the trust in ca to issue trustworthy certificates
	// (issuer trust in ca, when using k)
	private final CertainTrust o_it;

	// count of positive experiences
	private int positive;

	// count of positive experiences
	private int negative;

	public TrustAssessment(PublicKey k, Principal ca, Set<TrustCertificate> S,
			Option<CertainTrust> o_kl, CertainTrust o_it,
			int positive, int negative) {
		this.k = k;
		this.ca = ca;
		this.S = S;
		this.o_kl = o_kl;
		this.o_it = o_it;
		this.positive = positive;
		this.negative = negative;
	}

	public TrustAssessment(PublicKey k, Principal ca, TrustCertificate S,
			Option<CertainTrust> o_kl, CertainTrust o_it,
			int positive, int negative) {
		this.k = k;
		this.ca = ca;
		this.S = new HashSet<>();
		this.S.add(S);
		this.o_kl = o_kl;
		this.o_it = o_it;
		this.positive = positive;
		this.negative = negative;
	}

	@Override
	public TrustAssessment clone() {
		return o_kl.isSet()
				? new TrustAssessment(
						k, ca, new HashSet<>(S),
						new Option<CertainTrust>(o_kl.get().clone()), o_it.clone(),
						positive, negative)
				: new TrustAssessment(
						k, ca, new HashSet<>(S),
						new Option<CertainTrust>(), o_it.clone(),
						positive, negative);
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
		       o_it.getT() + ", " + o_it.getC() + ", " + o_it.getF() + "), " +
		       positive + ", " + negative + ")";
	}

	public PublicKey getK() {
		return k;
	}

	public Principal getCa() {
		return ca;
	}

	public Set<TrustCertificate> getS() {
		return S;
	}

	public Option<CertainTrust> getO_kl() {
		return o_kl;
	}

	public CertainTrust getO_it() {
		return o_it;
	}

	public int getPositive() {
		return positive;
	}

	public int getNegative() {
		return negative;
	}

	public void incPositive() {
		positive++;
	}

	public void incNegative() {
		negative++;
	}
}
