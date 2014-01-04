package data.sqlite;

import java.security.Principal;
import java.security.PublicKey;
import java.util.Collection;
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
	public Collection<TrustAssessment> getAssessments() {
		//TODO: implement
		return Collections.emptyList();
	}

	@Override
	public Collection<TrustCertificate> getTrustedCertificates() {
		//TODO: implement
		return Collections.emptyList();
	}

	@Override
	public Collection<TrustCertificate> getUntrustedCertificates() {
		//TODO: implement
		return Collections.emptyList();
	}

	@Override
	public void setTrustedCertificate(TrustCertificate S) {
		//TODO: implement
	}

	@Override
	public void setUntrustedCertificate(TrustCertificate S) {
		//TODO: implement
	}
}
