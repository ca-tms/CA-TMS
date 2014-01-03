package data;

import java.security.Principal;
import java.security.PublicKey;

import data.sqlite.SQLiteBackedTrustView;

public abstract class TrustView {
	private static TrustView instance = null;

	public static synchronized TrustView getInstance() {
		if (instance == null)
			instance = new SQLiteBackedTrustView();
		return instance;
	}

	public boolean hasTrustAssessment(PublicKey k, Principal ca) {
		return getAssessment(k, ca) != null;
	}

	public abstract TrustAssessment setAssessment(TrustAssessment assessment);

	public abstract TrustAssessment getAssessment(PublicKey k, Principal ca);

	public abstract Iterable<TrustAssessment> getAssessments();
}