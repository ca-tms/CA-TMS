package data.sqlite;

import java.security.Principal;
import java.security.PublicKey;
import java.util.Collections;

import data.TrustAssessment;
import data.TrustView;

public class SQLiteBackedTrustView extends TrustView {

	@Override
	public TrustAssessment setAssessment(TrustAssessment assessment) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TrustAssessment getAssessment(PublicKey k, Principal ca) {
		return null;
	}

	@Override
	public Iterable<TrustAssessment> getAssessments() {
		return Collections.emptyList();
	}
}
