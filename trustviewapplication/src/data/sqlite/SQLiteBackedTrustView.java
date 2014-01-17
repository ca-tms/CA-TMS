package data.sqlite;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import buisness.TrustComputation;

import CertainTrust.CertainTrust;

import util.Option;

import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

public class SQLiteBackedTrustView implements TrustView {
	private boolean isClosed = false;
	private final Connection connection;

	private final PreparedStatement getAssessment;
	private final PreparedStatement getAssessments;
	private final PreparedStatement getAssessmentsS;
	private final PreparedStatement setAssessment;
	private final PreparedStatement setAssessmentS;
	private final PreparedStatement getCertificateTrust;
	private final PreparedStatement setCertificateTrust;

	public SQLiteBackedTrustView(Connection connection) throws SQLException {
		this.connection = connection;

		getAssessment = connection.prepareStatement(
				"SELECT * FROM assessments WHERE k=? AND ca=?");

		getAssessments = connection.prepareStatement(
				"SELECT * FROM assessments");

		getAssessmentsS = connection.prepareStatement(
				"SELECT * FROM certificates WHERE publickey=? AND subject=? AND S=1");

		setAssessment = connection.prepareStatement(
				"INSERT OR REPLACE INTO assessments VALUES (?, ?, ?, ?, ?, ?, " +
				"                                           ?, ?, ?, ?, ?)");

		setAssessmentS = connection.prepareStatement(
				"INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?, " +
						"  COALESCE((SELECT trusted FROM certificates " +
						"            WHERE serial=? AND issuer=?), 0)," +
						"  COALESCE((SELECT untrusted FROM certificates " +
						"            WHERE serial=? AND issuer=?), 0)," +
						"  1)");

		getCertificateTrust = connection.prepareStatement(
				"SELECT * FROM certificates WHERE trusted=? AND untrusted=?");

		setCertificateTrust = connection.prepareStatement(
				"INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?, ?, ?, " +
				"  COALESCE((SELECT S FROM certificates WHERE serial=? AND issuer=?), 0))");
	}

	@Override
	public TrustAssessment getAssessment(TrustCertificate S) {
		return getAssessment(S.getPublicKey(), S.getSubject());
	}

	@Override
	public TrustAssessment getAssessment(String k, String ca) {
		checkClosed();
		TrustAssessment assessment = null;
		try {
			getAssessment.setString(1, k);
			getAssessment.setString(2, ca);
			try (ResultSet result = getAssessment.executeQuery()) {
				if (result.next()) {
					Set<TrustCertificate> S = new HashSet<>();
					getAssessmentsS.setString(1, result.getString(1));
					getAssessmentsS.setString(2, result.getString(2));
					try (ResultSet resultS = getAssessmentsS.executeQuery()) {
						while (resultS.next())
							S.add(new TrustCertificate(
									resultS.getString(1), resultS.getString(2),
									resultS.getString(3), resultS.getString(4)));
					}

					Option<CertainTrust> o_kl = new Option<CertainTrust>();
					double t = result.getDouble(3);
					if (!result.wasNull()) {
						double c = result.getDouble(4);
						if (!result.wasNull()) {
							double f = result.getDouble(5);
							if (!result.wasNull())
								o_kl = new Option<CertainTrust>(
										new CertainTrust(t, c, f, TrustComputation.opinionN));
						}
					}

					assessment = new TrustAssessment(
							result.getString(1), result.getString(2), S, o_kl,
							new CertainTrust(
									result.getDouble(6), result.getDouble(7),
									result.getDouble(8), TrustComputation.opinionN),
							new CertainTrust(
									result.getDouble(9), result.getDouble(10),
									result.getDouble(11), TrustComputation.opinionN));
				}
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
		return assessment;
	}

	@Override
	public void setAssessment(TrustAssessment assessment) {
		checkClosed();
		try {
			setAssessment.setString(1, assessment.getK());
			setAssessment.setString(2, assessment.getCa());
			if (assessment.getO_kl().isSet()) {
				setAssessment.setDouble(3, assessment.getO_kl().get().getT());
				setAssessment.setDouble(4, assessment.getO_kl().get().getC());
				setAssessment.setDouble(5, assessment.getO_kl().get().getF());
			}
			else {
				setAssessment.setNull(3, Types.INTEGER);
				setAssessment.setNull(4, Types.INTEGER);
				setAssessment.setNull(5, Types.INTEGER);
			}
			setAssessment.setDouble(6, assessment.getO_it_ca().getT());
			setAssessment.setDouble(7, assessment.getO_it_ca().getC());
			setAssessment.setDouble(8, assessment.getO_it_ca().getF());
			setAssessment.setDouble(9, assessment.getO_it_ee().getT());
			setAssessment.setDouble(10, assessment.getO_it_ee().getC());
			setAssessment.setDouble(11, assessment.getO_it_ee().getF());
			setAssessment.executeUpdate();

			for (TrustCertificate cert : assessment.getS()) {
				setAssessmentS.setString(1, cert.getSerial());
				setAssessmentS.setString(2, cert.getIssuer());
				setAssessmentS.setString(3, cert.getSubject());
				setAssessmentS.setString(4, cert.getPublicKey());
				setAssessmentS.setString(5, cert.getSerial());
				setAssessmentS.setString(6, cert.getIssuer());
				setAssessmentS.setString(7, cert.getSerial());
				setAssessmentS.setString(8, cert.getIssuer());
				setAssessmentS.executeUpdate();
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public Collection<TrustAssessment> getAssessments() {
		checkClosed();
		List<TrustAssessment> assessments = new ArrayList<>();
		try {
			try (ResultSet result = getAssessments.executeQuery()) {
				while (result.next()) {
					Set<TrustCertificate> S = new HashSet<>();
					getAssessmentsS.setString(1, result.getString(1));
					getAssessmentsS.setString(2, result.getString(2));
					try (ResultSet resultS = getAssessmentsS.executeQuery()) {
						while (resultS.next())
							S.add(new TrustCertificate(
									resultS.getString(1), resultS.getString(2),
									resultS.getString(3), resultS.getString(4)));
					}

					Option<CertainTrust> o_kl = new Option<CertainTrust>();
					double t = result.getDouble(3);
					if (!result.wasNull()) {
						double c = result.getDouble(4);
						if (!result.wasNull()) {
							double f = result.getDouble(5);
							if (!result.wasNull())
								o_kl = new Option<CertainTrust>(
										new CertainTrust(t, c, f, TrustComputation.opinionN));
						}
					}

					assessments.add(new TrustAssessment(
							result.getString(1), result.getString(2), S, o_kl,
							new CertainTrust(
									result.getDouble(6), result.getDouble(7),
									result.getDouble(8), TrustComputation.opinionN),
							new CertainTrust(
									result.getDouble(9), result.getDouble(10),
									result.getDouble(11), TrustComputation.opinionN)));
				}
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
		return assessments;
	}

	@Override
	public Collection<TrustCertificate> getTrustedCertificates() {
		checkClosed();
		Set<TrustCertificate> certificates = new HashSet<>();
		try {
			getCertificateTrust.setInt(1, 1);
			getCertificateTrust.setInt(2, 0);
			try (ResultSet result = getCertificateTrust.executeQuery()) {
				while (result.next())
					certificates.add(new TrustCertificate(
							result.getString(1), result.getString(2),
							result.getString(3), result.getString(4)));
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
		return certificates;
	}

	@Override
	public Collection<TrustCertificate> getUntrustedCertificates() {
		checkClosed();
		Set<TrustCertificate> certificates = new HashSet<>();
		try {
			getCertificateTrust.setInt(1, 0);
			getCertificateTrust.setInt(2, 1);
			try (ResultSet result = getCertificateTrust.executeQuery()) {
				while (result.next())
					certificates.add(new TrustCertificate(
							result.getString(1), result.getString(2),
							result.getString(3), result.getString(4)));
			}
			return certificates;
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
		return certificates;
	}

	@Override
	public void setTrustedCertificate(TrustCertificate S) {
		checkClosed();
		try {
			setCertificateTrust.setString(1, S.getSerial());
			setCertificateTrust.setString(2, S.getIssuer());
			setCertificateTrust.setString(3, S.getSubject());
			setCertificateTrust.setString(4, S.getPublicKey());
			setCertificateTrust.setInt(5, 1);
			setCertificateTrust.setInt(6, 0);
			setCertificateTrust.setString(7, S.getSerial());
			setCertificateTrust.setString(8, S.getIssuer());
			setCertificateTrust.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void setUntrustedCertificate(TrustCertificate S) {
		checkClosed();
		try {
			setCertificateTrust.setString(1, S.getSerial());
			setCertificateTrust.setString(2, S.getIssuer());
			setCertificateTrust.setString(3, S.getSubject());
			setCertificateTrust.setString(4, S.getPublicKey());
			setCertificateTrust.setInt(5, 0);
			setCertificateTrust.setInt(6, 1);
			setCertificateTrust.setString(7, S.getSerial());
			setCertificateTrust.setString(8, S.getIssuer());
			setCertificateTrust.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void close() throws Exception {
		isClosed = true;
		connection.commit();
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
