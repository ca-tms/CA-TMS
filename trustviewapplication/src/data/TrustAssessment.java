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
	private final Set<Certificate> S;

	// opinion whether k belongs to ca (key legitimacy)
	private final Option<CertainTrust> o_kl;

	// opinion on the trust in ca to issue trustworthy certificates
	// (issuer trust in ca, when using k)
	private final CertainTrust o_it;

	public TrustAssessment(PublicKey k, Principal ca, Set<Certificate> S,
			Option<CertainTrust> o_kl, CertainTrust o_it) {
		this.k = k;
		this.ca = ca;
		this.S = S;
		this.o_kl = o_kl;
		this.o_it = o_it;
	}

	public TrustAssessment(PublicKey k, Principal ca, Certificate S,
			Option<CertainTrust> o_kl, CertainTrust o_it) {
		this.k = k;
		this.ca = ca;
		this.S = new HashSet<>();
		this.S.add(S);
		this.o_kl = o_kl;
		this.o_it = o_it;
	}

	public PublicKey getK() {
		return k;
	}

	public Principal getCa() {
		return ca;
	}

	public Set<Certificate> getS() {
		return S;
	}

	public Option<CertainTrust> getO_kl() {
		return o_kl;
	}

	public CertainTrust getO_it() {
		return o_it;
	}
}
