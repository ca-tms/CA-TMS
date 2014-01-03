package data.sqlite;

import java.security.Principal;
import java.security.PublicKey;
import java.util.Collections;

import data.TrustCertificate;
import data.TrustAssessment;
import data.TrustView;

public class SQLiteBackedTrustView extends TrustView {

	@Override
	public void setAssessment(TrustAssessment assessment) {
		//TODO: implement
	}

	@Override
	public TrustAssessment getAssessment(PublicKey k, Principal ca) {
		//TODO: implement
		return null;
	}

	@Override
	public Iterable<TrustAssessment> getAssessments() {
		//TODO: implement
		return Collections.emptyList();
	}

	@Override
	public Iterable<TrustCertificate> getTrustedCertificates() {
		//TODO: implement
		return Collections.emptyList();
	}

	@Override
	public Iterable<TrustCertificate> getUntrustedCertificates() {
		//TODO: implement
		return Collections.emptyList();
	}
}
