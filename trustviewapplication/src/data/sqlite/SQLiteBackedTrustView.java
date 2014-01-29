package data.sqlite;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
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

	// TODO: this parameters should be configurable and globally accessible
	//       (maybe stored in the database)
	// TODO: currently the time stamp is updated only if the assessment is updated
	//       should it be updated when the assessment is just used?
	//       even only to initialize other assessments for the first time?
	//       if it is inside a chain that fails to validate?
	// TODO: Should trusted/untrusted certificates also be removed?
	//       maybe when they expire?
	private static final long ASSESSMENT_EXPIRATION_MILLIS = 365*24*60*60*1000;

	private final PreparedStatement getAssessment;
	private final PreparedStatement getAssessments;
	private final PreparedStatement getAssessmentsS;
	private final PreparedStatement setAssessment;
	private final PreparedStatement setAssessmentS;
	private final PreparedStatement getCertificateTrust;
	private final PreparedStatement setCertificateTrust;
	private final PreparedStatement removeAssessment;
	private final PreparedStatement cleanCertificates;

	public SQLiteBackedTrustView(Connection connection) throws SQLException {
		this.connection = connection;

		// retrieving assessments
		getAssessment = connection.prepareStatement(
				"SELECT * FROM assessments WHERE k=? AND ca=?");

		getAssessments = connection.prepareStatement(
				"SELECT * FROM assessments");

		getAssessmentsS = connection.prepareStatement(
				"SELECT * FROM certificates WHERE publickey=? AND subject=? AND S=1");

		// setting assessments
		setAssessment = connection.prepareStatement(
				"INSERT OR REPLACE INTO assessments VALUES (?, ?, ?, ?, ?, ?, " +
				"                                           ?, ?, ?, ?, ?, ?)");

		setAssessmentS = connection.prepareStatement(
				"INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?, " +
				"  COALESCE((SELECT trusted FROM certificates " +
				"            WHERE serial=? AND issuer=?), 0)," +
				"  COALESCE((SELECT untrusted FROM certificates " +
				"            WHERE serial=? AND issuer=?), 0)," +
				"  ?)");

		// retrieving certificates
		getCertificateTrust = connection.prepareStatement(
				"SELECT * FROM certificates WHERE trusted=? AND untrusted=?");

		// setting certificates
		setCertificateTrust = connection.prepareStatement(
				"INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?, ?, ?, " +
				"  COALESCE((SELECT S FROM certificates WHERE serial=? AND issuer=?), 0))");

		// cleaning the trust view
		removeAssessment = connection.prepareStatement(
				"DELETE FROM assessments WHERE k=? AND ca=?");

		cleanCertificates = connection.prepareStatement(
				"DELETE FROM certificates WHERE trusted=0 AND untrusted=0 AND S=0");
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

	// this is also updating the time stamp
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
			setAssessment.setTimestamp(12, new Timestamp(new Date().getTime()));
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
				setAssessmentS.setBoolean(9, true);
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
			getCertificateTrust.setBoolean(1, true);
			getCertificateTrust.setBoolean(2, false);
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
			getCertificateTrust.setBoolean(1, false);
			getCertificateTrust.setBoolean(2, true);
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
			setCertificateTrust.setBoolean(5, true);
			setCertificateTrust.setBoolean(6, false);
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
			setCertificateTrust.setBoolean(5, false);
			setCertificateTrust.setBoolean(6, true);
			setCertificateTrust.setString(7, S.getSerial());
			setCertificateTrust.setString(8, S.getIssuer());
			setCertificateTrust.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void clean() {
		checkClosed();
		try {
			final long nowMillis = new Date().getTime();
			try (ResultSet result = getAssessments.executeQuery()) {
				while (result.next())
					if (nowMillis - result.getTimestamp(12).getTime()
							> ASSESSMENT_EXPIRATION_MILLIS) {
						getAssessmentsS.setString(1, result.getString(1));
						getAssessmentsS.setString(2, result.getString(2));
						try (ResultSet resultS = getAssessmentsS.executeQuery()) {
							while (resultS.next()) {
								setAssessmentS.setString(1, resultS.getString(1));
								setAssessmentS.setString(2, resultS.getString(2));
								setAssessmentS.setString(3, resultS.getString(3));
								setAssessmentS.setString(4, resultS.getString(4));
								setAssessmentS.setString(5, resultS.getString(1));
								setAssessmentS.setString(6, resultS.getString(2));
								setAssessmentS.setString(7, resultS.getString(1));
								setAssessmentS.setString(8, resultS.getString(2));
								setAssessmentS.setBoolean(9, false);
								setAssessmentS.executeUpdate();
							}
						}

						removeAssessment.setString(1, result.getString(1));
						removeAssessment.setString(2, result.getString(2));
						removeAssessment.executeUpdate();
					}
			}
			cleanCertificates.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void save() throws SQLException {
		try {
			connection.commit();
		}
		catch (SQLException e) {
			connection.rollback();
			throw e;
		}
	}

	@Override
	public void close() throws SQLException {
		isClosed = true;

		getAssessment.close();
		getAssessments.close();
		getAssessmentsS.close();
		setAssessment.close();
		setAssessmentS.close();
		getCertificateTrust.close();
		setCertificateTrust.close();
		removeAssessment.close();
		cleanCertificates.close();

		connection.rollback();
		connection.close();
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
