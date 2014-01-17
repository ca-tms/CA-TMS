package data.sqlite;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Collections;

import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

public class SQLiteBackedTrustView implements TrustView {
	private boolean isClosed = false;
	private Connection connection;

	public SQLiteBackedTrustView(Connection connection) throws SQLException {
		this.connection = connection;
	}

	@Override
	public TrustAssessment getAssessment(TrustCertificate S) {
		return getAssessment(S.getPublicKey(), S.getSubject());
	}

	@Override
	public TrustAssessment getAssessment(String k, String ca) {
		checkClosed();
		//TODO: implement
		return null;
	}

	@Override
	public void setAssessment(TrustAssessment assessment) {
		checkClosed();
		//TODO: implement
	}

	@Override
	public Collection<TrustAssessment> getAssessments() {
		checkClosed();
		//TODO: implement
		return Collections.emptyList();
	}

	@Override
	public Collection<TrustCertificate> getTrustedCertificates() {
		checkClosed();
		//TODO: implement
		return Collections.emptyList();
	}

	@Override
	public Collection<TrustCertificate> getUntrustedCertificates() {
		checkClosed();
		//TODO: implement
		return Collections.emptyList();
	}

	@Override
	public void setTrustedCertificate(TrustCertificate S) {
		checkClosed();
		//TODO: implement
	}

	@Override
	public void setUntrustedCertificate(TrustCertificate S) {
		checkClosed();
		//TODO: implement
	}

	@Override
	public void close() throws SQLException {
		try {
			isClosed = true;
			connection.commit();
		}
		catch (SQLException e) {
			connection.rollback();
			throw e;
		}
	}

	public boolean isClosed() {
		return isClosed;
	}

	private void checkClosed() {
		if (isClosed)
			throw new UnsupportedOperationException(
					"Cannot access a TrustView that is already closed.");
	}
}
