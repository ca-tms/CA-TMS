package buisness;

import java.security.PublicKey;
import java.util.Set;

import CertainTrust.CertainTrust;

public class TrustAssessment {
	private final PublicKey k; // public key
	private final String ca; // CA name
	private final Set<Integer> S; // certificates (as IDs) for k
	private final CertainTrust o_kl; // opinion whether k belongs to ca (key legitimacy)
	private final CertainTrust o_it; // opinion on the trust in ca to issue trustworthy
	                                 // certificates
	                                 // (issuer trust in ca, when using k)

	public TrustAssessment(PublicKey k, String ca, Set<Integer> S,
			CertainTrust o_kl, CertainTrust o_it) {
		this.k = k;
		this.ca = ca;
		this.S = S;
		this.o_kl = o_kl;
		this.o_it = o_it;
	}

	public PublicKey getK() {
		return k;
	}

	public String getCa() {
		return ca;
	}

	public Set<Integer> getS() {
		return S;
	}

	public CertainTrust getO_kl() {
		return o_kl;
	}

	public CertainTrust getO_it() {
		return o_it;
	}
}
