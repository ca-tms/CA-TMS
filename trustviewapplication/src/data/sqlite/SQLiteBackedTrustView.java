package data.sqlite;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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

import CertainTrust.CertainTrust;

import util.Option;

import data.Configuration;
import data.Model;
import data.ModelAccessException;
import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

/**
 * Implementation of the {@link TrustView} that is backed by a SQLite database.
 */
public class SQLiteBackedTrustView implements TrustView {
	private final Connection connection;
	private final Configuration config;

	private final PreparedStatement getAssessment;
	private final PreparedStatement getAssessments;
	private final PreparedStatement getAssessmentsS;
	private final PreparedStatement setAssessment;
	private final PreparedStatement setAssessmentS;
	private final PreparedStatement setAssessmentValid;
	private final PreparedStatement getCertificates;
	private final PreparedStatement getCertificateTrust;
	private final PreparedStatement setCertificateTrust;
	private final PreparedStatement getCertificatesForHost;
	private final PreparedStatement addCertificateToHost;
	private final PreparedStatement addCertificateToWatchlist;
	private final PreparedStatement setWatchlistCertificate;
	private final PreparedStatement removeCertificateFromWatchlist;
	private final PreparedStatement getWatchlistCertificate;
	private final PreparedStatement getWatchlistCertificates;
	private final PreparedStatement removeAssessment;
	private final PreparedStatement removeCertificate;
	private final PreparedStatement cleanCertificates;
	private final PreparedStatement eraseAssessments;
	private final PreparedStatement eraseCertificates;

	public SQLiteBackedTrustView(Connection connection) throws ModelAccessException  {
		try {
			this.connection = connection;

			// configuration values
			config = Model.openConfiguration();

			try {
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
						"                                           ?, ?, ?, ?, ?, ?, " +
						"                                           ?, ?, ?, ?, ?, ?)");

				setAssessmentS = connection.prepareStatement(
						"INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?, ?, ?, ?, " +
						"  COALESCE((SELECT trusted FROM certificates " +
						"            WHERE serial=? AND issuer=?), 0)," +
						"  COALESCE((SELECT untrusted FROM certificates " +
						"            WHERE serial=? AND issuer=?), 0)," +
						"  ?)");

				setAssessmentValid = connection.prepareStatement(
						"UPDATE assessments SET timestamp=? WHERE k=? AND ca=?");

				// retrieving certificates
				getCertificates = connection.prepareStatement(
						"SELECT * FROM certificates");

				getCertificateTrust = connection.prepareStatement(
						"SELECT * FROM certificates WHERE trusted=? AND untrusted=?");

				// setting certificates
				setCertificateTrust = connection.prepareStatement(
						"INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, " +
						"  COALESCE((SELECT S FROM certificates WHERE serial=? AND issuer=?), 0))");

				// accessing certificate hosts
				getCertificatesForHost = connection.prepareStatement(
						"SELECT * FROM certificates JOIN certhosts" +
						"  ON certificates.serial = certhosts.serial" +
						"  AND certificates.issuer = certhosts.issuer" +
						"  WHERE certhosts.host=?");

				addCertificateToHost = connection.prepareStatement(
						"INSERT OR IGNORE INTO certhosts VALUES (?, ?, ?)");

				// watchlist
				addCertificateToWatchlist = connection.prepareStatement(
						"INSERT OR IGNORE INTO watchlist VALUES (?, ?, ?)");

				setWatchlistCertificate = connection.prepareStatement(
						"INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?, ?, ?, ?, " +
						"  COALESCE((SELECT trusted FROM certificates WHERE serial=? AND issuer=?), 0)," +
						"  COALESCE((SELECT untrusted FROM certificates WHERE serial=? AND issuer=?), 0)," +
						"  COALESCE((SELECT S FROM certificates WHERE serial=? AND issuer=?), 0))");

				removeCertificateFromWatchlist = connection.prepareStatement(
						"DELETE FROM watchlist WHERE serial=? AND issuer=?");

				getWatchlistCertificate = connection.prepareStatement(
						"SELECT * FROM certificates JOIN watchlist" +
						"  ON certificates.serial = watchlist.serial" +
						"  AND certificates.issuer = watchlist.issuer" +
						"  WHERE certificates.serial=? AND certificates.issuer=?");

				getWatchlistCertificates = connection.prepareStatement(
						"SELECT * FROM certificates JOIN watchlist" +
						"  ON certificates.serial = watchlist.serial" +
						"  AND certificates.issuer = watchlist.issuer");

				// cleaning the trust view
				removeAssessment = connection.prepareStatement(
						"DELETE FROM assessments WHERE k=? AND ca=?");

				removeCertificate = connection.prepareStatement(
						"DELETE FROM certificates WHERE serial=? AND issuer=?");

				cleanCertificates = connection.prepareStatement(
						"DELETE FROM certificates WHERE trusted=0 AND untrusted=0 AND S=0");

				// erasing the trust view
				eraseAssessments = connection.prepareStatement(
						"DELETE FROM assessments");

				eraseCertificates = connection.prepareStatement(
						"DELETE FROM certificates");
			}
			catch (SQLException e) {
				throw new ModelAccessException(e);
			}
		}
		catch (Throwable t) {
			try {
				finalizeConnection();
			}
			catch (Throwable u) {
				t.addSuppressed(u);
			}
			throw t;
		}
	}

	@Override
	public TrustAssessment getAssessment(TrustCertificate S) {
		return getAssessment(S.getPublicKey(), S.getSubject());
	}

	@Override
	public TrustAssessment getAssessment(String k, String ca) {
		TrustAssessment assessment = null;
		try {
			validateDatabaseConnection();
			getAssessment.setString(1, k);
			getAssessment.setString(2, ca);
			try (ResultSet result = getAssessment.executeQuery()) {
				if (result.next())
					assessment = constructAssessment(result);
			}
		}
		catch (SQLException | CertificateException e) {
			e.printStackTrace();
		}
		return assessment;
	}

	@Override
	public void setAssessment(TrustAssessment assessment) {
		try {
			validateDatabaseConnection();
			setAssessment.setString(1, assessment.getK());
			setAssessment.setString(2, assessment.getCa());
			if (assessment.getO_kl().isSet()) {
				setAssessment.setDouble(3, assessment.getO_kl().get().getT());
				setAssessment.setDouble(4, assessment.getO_kl().get().getC());
				setAssessment.setDouble(5, assessment.getO_kl().get().getF());
				setAssessment.setDouble(6, assessment.getO_kl().get().getR());
				setAssessment.setDouble(7, assessment.getO_kl().get().getS());
			}
			else {
				setAssessment.setNull(3, Types.REAL);
				setAssessment.setNull(4, Types.REAL);
				setAssessment.setNull(5, Types.REAL);
				setAssessment.setNull(6, Types.REAL);
				setAssessment.setNull(7, Types.REAL);
			}
			setAssessment.setDouble(8, assessment.getO_it_ca().getT());
			setAssessment.setDouble(9, assessment.getO_it_ca().getC());
			setAssessment.setDouble(10, assessment.getO_it_ca().getF());
			setAssessment.setDouble(11, assessment.getO_it_ca().getR());
			setAssessment.setDouble(12, assessment.getO_it_ca().getS());
			setAssessment.setDouble(13, assessment.getO_it_ee().getT());
			setAssessment.setDouble(14, assessment.getO_it_ee().getC());
			setAssessment.setDouble(15, assessment.getO_it_ee().getF());
			setAssessment.setDouble(16, assessment.getO_it_ee().getR());
			setAssessment.setDouble(17, assessment.getO_it_ee().getS());
			setAssessment.setTimestamp(18, new Timestamp(new Date().getTime()));
			setAssessment.executeUpdate();

			for (TrustCertificate cert : assessment.getS()) {
				setAssessmentS.setString(1, cert.getSerial());
				setAssessmentS.setString(2, cert.getIssuer());
				setAssessmentS.setString(3, cert.getSubject());
				setAssessmentS.setString(4, cert.getPublicKey());
				setAssessmentS.setTimestamp(5, new Timestamp(cert.getNotBefore().getTime()));
				setAssessmentS.setTimestamp(6, new Timestamp(cert.getNotAfter().getTime()));
				if (cert.getCertificate() != null)
					setAssessmentS.setBytes(7, cert.getCertificate().getEncoded());
				else
					setAssessmentS.setNull(7, Types.BLOB);
				setAssessmentS.setString(8, cert.getSerial());
				setAssessmentS.setString(9, cert.getIssuer());
				setAssessmentS.setString(10, cert.getSerial());
				setAssessmentS.setString(11, cert.getIssuer());
				setAssessmentS.setBoolean(12, true);
				setAssessmentS.executeUpdate();
			}
		}
		catch (SQLException | CertificateEncodingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void setAssessmentValid(String k, String ca) {
		try {
			validateDatabaseConnection();
			setAssessmentValid.setTimestamp(1, new Timestamp(new Date().getTime()));
			setAssessmentValid.setString(2, k);
			setAssessmentValid.setString(3, ca);
			setAssessmentValid.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void removeAssessment(String k, String ca) {
		try {
			validateDatabaseConnection();
			removeAssessment.setString(1, k);
			removeAssessment.setString(2, ca);
			removeAssessment.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public Collection<TrustAssessment> getAssessments() {
		List<TrustAssessment> assessments = new ArrayList<>();
		try {
			validateDatabaseConnection();
			try (ResultSet result = getAssessments.executeQuery()) {
				while (result.next())
					assessments.add(constructAssessment(result));
			}
		}
		catch (SQLException | CertificateException e) {
			e.printStackTrace();
		}
		return assessments;
	}

	@Override
	public Collection<TrustCertificate> getTrustedCertificates() {
		Set<TrustCertificate> certificates = new HashSet<>();
		try {
			validateDatabaseConnection();
			getCertificateTrust.setBoolean(1, true);
			getCertificateTrust.setBoolean(2, false);
			try (ResultSet result = getCertificateTrust.executeQuery()) {
				while (result.next())
					certificates.add(constructCertificate(result));
			}
		}
		catch (SQLException | CertificateException e) {
			e.printStackTrace();
		}
		return certificates;
	}

	@Override
	public Collection<TrustCertificate> getUntrustedCertificates() {
		Set<TrustCertificate> certificates = new HashSet<>();
		try {
			validateDatabaseConnection();
			getCertificateTrust.setBoolean(1, false);
			getCertificateTrust.setBoolean(2, true);
			try (ResultSet result = getCertificateTrust.executeQuery()) {
				while (result.next())
					certificates.add(constructCertificate(result));
			}
			return certificates;
		}
		catch (SQLException | CertificateException e) {
			e.printStackTrace();
		}
		return certificates;
	}

	@Override
	public void setTrustedCertificate(TrustCertificate S) {
		try {
			validateDatabaseConnection();
			writeCertificateTrust(S, true, false);
		}
		catch (SQLException | CertificateEncodingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void setUntrustedCertificate(TrustCertificate S) {
		try {
			validateDatabaseConnection();
			writeCertificateTrust(S, false, true);
		}
		catch (SQLException | CertificateEncodingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void removeCertificate(TrustCertificate S) {
		try {
			validateDatabaseConnection();
			writeCertificateTrust(S, false, false);
		}
		catch (SQLException | CertificateEncodingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public Collection<TrustCertificate> getCertificatesForHost(String host) {
		Set<TrustCertificate> certificates = new HashSet<>();
		try {
			validateDatabaseConnection();
			getCertificatesForHost.setString(1, host);
			try (ResultSet result = getCertificatesForHost.executeQuery()) {
				while (result.next())
					certificates.add(constructCertificate(result));
			}
			return certificates;
		}
		catch (SQLException | CertificateException e) {
			e.printStackTrace();
		}
		return certificates;
	}

	@Override
	public void addHostForCertificate(TrustCertificate certificate, String host) {
		try {
			validateDatabaseConnection();
			addCertificateToHost.setString(1, certificate.getSerial());
			addCertificateToHost.setString(2, certificate.getIssuer());
			addCertificateToHost.setString(3, host);
			addCertificateToHost.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void addCertificateToWatchlist(TrustCertificate certificate) {
		try {
			validateDatabaseConnection();

			setWatchlistCertificate.setString(1, certificate.getSerial());
			setWatchlistCertificate.setString(2, certificate.getIssuer());
			setWatchlistCertificate.setString(3, certificate.getSubject());
			setWatchlistCertificate.setString(4, certificate.getPublicKey());
			setWatchlistCertificate.setTimestamp(5, new Timestamp(certificate.getNotBefore().getTime()));
			setWatchlistCertificate.setTimestamp(6, new Timestamp(certificate.getNotAfter().getTime()));
			if (certificate.getCertificate() != null)
				setWatchlistCertificate.setBytes(7, certificate.getCertificate().getEncoded());
			else
				setWatchlistCertificate.setNull(7, Types.BLOB);
			setWatchlistCertificate.executeUpdate();

			addCertificateToWatchlist.setString(1, certificate.getSerial());
			addCertificateToWatchlist.setString(2, certificate.getIssuer());
			addCertificateToWatchlist.setTimestamp(3, new Timestamp(new Date().getTime()));
			addCertificateToWatchlist.executeUpdate();
		}
		catch (SQLException | CertificateException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void removeCertificateFromWatchlist(TrustCertificate certificate) {
		try {
			validateDatabaseConnection();
			removeCertificateFromWatchlist.setString(1, certificate.getSerial());
			removeCertificateFromWatchlist.setString(2, certificate.getIssuer());
			removeCertificateFromWatchlist.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public boolean isCertificateOnWatchlist(TrustCertificate certificate) {
		try {
			getWatchlistCertificate.setString(1, certificate.getSerial());
			getWatchlistCertificate.setString(2, certificate.getIssuer());
			try (ResultSet result = getWatchlistCertificate.executeQuery()) {
				if (result.next())
					return true;
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public Collection<TrustCertificate> getWatchlist() {
		List<TrustCertificate> watchlist = new ArrayList<>();
		try {
			try (ResultSet result = getWatchlistCertificates.executeQuery()) {
				while (result.next())
					watchlist.add(constructCertificate(result));
			}
		}
		catch (SQLException | CertificateException e) {
			e.printStackTrace();
		}
		return watchlist;
	}

	@Override
	public Date getWatchlistCerrtificateTimestamp(TrustCertificate certificate) {
		try {
			getWatchlistCertificate.setString(1, certificate.getSerial());
			getWatchlistCertificate.setString(2, certificate.getIssuer());
			try (ResultSet result = getWatchlistCertificate.executeQuery()) {
				if (result.next())
					return result.getTimestamp(13);
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public void clean() {
		try {
			validateDatabaseConnection();
			final long watchlistExpirationMillis =
					config.get(Configuration.WATCHLIST_EXPIRATION_MILLIS, Long.class);
			final long assessmentExpirationMillis =
					config.get(Configuration.ASSESSMENT_EXPIRATION_MILLIS, Long.class);
			final long nowMillis = new Date().getTime();

			// remove expired watchlist certificates
			try (ResultSet result = getWatchlistCertificates.executeQuery()) {
				while (result.next())
					if (nowMillis - result.getTimestamp(13).getTime()
							> watchlistExpirationMillis) {
						removeCertificateFromWatchlist.setString(1, result.getString(1));
						removeCertificateFromWatchlist.setString(2, result.getString(2));
						removeCertificateFromWatchlist.executeUpdate();
					}
			}

			// remove expired assessments
			try (ResultSet result = getAssessments.executeQuery()) {
				while (result.next())
					if (nowMillis - result.getTimestamp(18).getTime()
							> assessmentExpirationMillis) {
						getAssessmentsS.setString(1, result.getString(1));
						getAssessmentsS.setString(2, result.getString(2));
						try (ResultSet resultS = getAssessmentsS.executeQuery()) {
							while (resultS.next()) {
								setAssessmentS.setString(1, resultS.getString(1));
								setAssessmentS.setString(2, resultS.getString(2));
								setAssessmentS.setString(3, resultS.getString(3));
								setAssessmentS.setString(4, resultS.getString(4));
								setAssessmentS.setString(5, resultS.getString(5));
								setAssessmentS.setString(6, resultS.getString(6));
								setAssessmentS.setString(7, resultS.getString(7));
								setAssessmentS.setString(8, resultS.getString(1));
								setAssessmentS.setString(9, resultS.getString(2));
								setAssessmentS.setString(10, resultS.getString(1));
								setAssessmentS.setString(11, resultS.getString(2));
								setAssessmentS.setBoolean(12, false);
								setAssessmentS.executeUpdate();
							}
						}

						removeAssessment.setString(1, result.getString(1));
						removeAssessment.setString(2, result.getString(2));
						removeAssessment.executeUpdate();
					}
			}

			// remove certificates that are no longer needed after
			// the removal of expired assessments
			cleanCertificates.executeUpdate();

			// remove expired certificates
			try (ResultSet result = getCertificates.executeQuery()) {
				while (result.next())
					if (result.getTimestamp(6).getTime() < nowMillis) {
						removeCertificate.setString(1, result.getString(1));
						removeCertificate.setString(2, result.getString(2));
						removeCertificate.executeUpdate();
					}
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void erase() {
		try {
			validateDatabaseConnection();
			eraseAssessments.executeUpdate();
			eraseCertificates.executeUpdate();
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void close() throws ModelAccessException {
		try {
			finalizeConnection();
		}
		catch (ModelAccessException e) {
			throw e;
		}
		catch (Exception e) {
			throw new ModelAccessException(e);
		}
	}

	private void finalizeConnection() throws ModelAccessException, SQLException {
		try {
			config.close();
			connection.commit();
		}
		catch (SQLException e) {
			connection.rollback();
			throw e;
		}
		finally {
			try {
				getAssessment.close();
				getAssessments.close();
				getAssessmentsS.close();
				setAssessment.close();
				setAssessmentS.close();
				setAssessmentValid.close();
				getCertificates.close();
				getCertificateTrust.close();
				setCertificateTrust.close();
				getCertificatesForHost.close();
				addCertificateToHost.close();
				addCertificateToWatchlist.close();
				setWatchlistCertificate.close();
				removeCertificateFromWatchlist.close();
				getWatchlistCertificate.close();
				getWatchlistCertificates.close();
				removeAssessment.close();
				removeCertificate.close();
				cleanCertificates.close();
				eraseAssessments.close();
				eraseCertificates.close();
			}
			finally {
				connection.close();
			}
		}
	}

	private void writeCertificateTrust(TrustCertificate S, boolean trusted, boolean untrusted)
			throws SQLException, CertificateEncodingException {
		setCertificateTrust.setString(1, S.getSerial());
		setCertificateTrust.setString(2, S.getIssuer());
		setCertificateTrust.setString(3, S.getSubject());
		setCertificateTrust.setString(4, S.getPublicKey());
		setCertificateTrust.setTimestamp(5, new Timestamp(S.getNotBefore().getTime()));
		setCertificateTrust.setTimestamp(6, new Timestamp(S.getNotAfter().getTime()));
		if (S.getCertificate() != null)
			setCertificateTrust.setBytes(7, S.getCertificate().getEncoded());
		else
			setCertificateTrust.setNull(7, Types.BLOB);
		setCertificateTrust.setBoolean(8, trusted);
		setCertificateTrust.setBoolean(9, untrusted);
		setCertificateTrust.setString(10, S.getSerial());
		setCertificateTrust.setString(11, S.getIssuer());
		setCertificateTrust.executeUpdate();
	}

	private TrustCertificate constructCertificate(ResultSet result)
			throws CertificateException, SQLException {
		TrustCertificate cert = null;

		byte[] blob = result.getBytes(7);
		if (!result.wasNull())
			cert = new TrustCertificate(
					CertificateFactory.getInstance("X.509").
						generateCertificate(
								new ByteArrayInputStream(blob)));

		if (cert != null && (
				!cert.getSerial().equals(result.getString(1)) ||
				!cert.getIssuer().equals(result.getString(2)) ||
				!cert.getSubject().equals(result.getString(3)) ||
				!cert.getPublicKey().equals(result.getString(4)) ||
				!cert.getNotBefore().equals(result.getTimestamp(5)) ||
				!cert.getNotAfter().equals(result.getTimestamp(6))))
			cert = null;

		if (cert == null)
			cert = new TrustCertificate(
					result.getString(1), result.getString(2),
					result.getString(3), result.getString(4),
					result.getTimestamp(5), result.getTimestamp(6));

		return cert;
	}

	private TrustAssessment constructAssessment(ResultSet result)
			throws CertificateException, SQLException {
		final int opinionN = config.get(Configuration.OPINION_N, Integer.class);

		Set<TrustCertificate> S = new HashSet<>();
		getAssessmentsS.setString(1, result.getString(1));
		getAssessmentsS.setString(2, result.getString(2));
		try (ResultSet resultS = getAssessmentsS.executeQuery()) {
			while (resultS.next())
				S.add(constructCertificate(resultS));
		}

		Option<CertainTrust> o_kl = new Option<CertainTrust>();
		double t = result.getDouble(3);
		if (!result.wasNull()) {
			double c = result.getDouble(4);
			if (!result.wasNull()) {
				double f = result.getDouble(5);
				if (!result.wasNull()) {
					if (!result.wasNull()) {
						double r = result.getDouble(6);
						if (!result.wasNull()) {
							if (!result.wasNull()) {
								double s = result.getDouble(7);
								if (!result.wasNull()) {
									o_kl = new Option<CertainTrust>(
											new CertainTrust(t, c, f, opinionN));
									o_kl.get().setRS(r, s);
								}
							}
						}
					}
				}
			}
		}

		CertainTrust o_it_ca = new CertainTrust(
				result.getDouble(8), result.getDouble(9),
				result.getDouble(10), opinionN);
		o_it_ca.setRS(result.getDouble(11), result.getDouble(12));

		CertainTrust o_it_ee = new CertainTrust(
				result.getDouble(13), result.getDouble(14),
				result.getDouble(15), opinionN);
		o_it_ee.setRS(result.getDouble(16), result.getDouble(17));

		return new TrustAssessment(
				result.getString(1), result.getString(2), S,
				o_kl, o_it_ca, o_it_ee);
	}

	private void validateDatabaseConnection() throws SQLException {
		if (connection.isClosed())
			throw new UnsupportedOperationException(
					"Cannot access a TrustView that is already closed.");
	}
}
