package data.sqlite;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import CertainTrust.CertainTrust;

import util.Option;

import data.CRLInfo;
import data.Configuration;
import data.Model;
import data.ModelAccessException;
import data.OCSPInfo;
import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

/**
 * Implementation of the {@link TrustView} that is backed by a SQLite database.
 */
public class SQLiteBackedTrustView implements TrustView {
	private final Connection connection;

	private final PreparedStatement getAssessment;
	private final PreparedStatement getAssessments;
	private final PreparedStatement getAssessmentsS;
	private final UpdateInsertStmnt setAssessment;
	private final UpdateInsertStmnt setAssessmentS;
	private final PreparedStatement setAssessmentValid;
	private final PreparedStatement getCertificate;
	private final PreparedStatement getCertificates;
	private final PreparedStatement getCertificateTrust;
	private final UpdateInsertStmnt setCertificateTrust;
	private final UpdateInsertStmnt setCertificateRevoked;
	private final UpdateInsertStmnt setCertificate;
	private final PreparedStatement getCertificatesForHost;
	private final PreparedStatement addCertificateToHost;
	private final PreparedStatement addCertificateToWatchlist;
	private final PreparedStatement removeCertificateFromWatchlist;
	private final PreparedStatement getWatchlistCertificate;
	private final PreparedStatement getWatchlistCertificates;
	private final UpdateInsertStmnt addCRL;
	private final PreparedStatement getCRL;
	private final UpdateInsertStmnt addOCSP;
	private final PreparedStatement getOCSP;
	private final PreparedStatement removeAssessment;
	private final PreparedStatement removeCertificate;
	private final PreparedStatement cleanCertificates;
	private final PreparedStatement eraseAssessments;
	private final PreparedStatement eraseCertificates;

	private final long watchlistExpirationMillis;
	private final long assessmentExpirationMillis;
	private final int opinionN;
	private final List<Notification> notifications = new ArrayList<>();

	// CRLs are not directly inserted into the data base but as batch
	// when finalizing the connection for performance reasons
	private final Map<CRLInfo, CRLInfo> deferredCRLBatch = new HashMap<>();

	public SQLiteBackedTrustView(Connection connection) throws ModelAccessException  {
		try {
			this.connection = connection;

			// configuration values
			try (Configuration config = Model.openConfiguration()) {
				watchlistExpirationMillis =
						config.get(Configuration.WATCHLIST_EXPIRATION_MILLIS, Long.class);
				assessmentExpirationMillis =
						config.get(Configuration.ASSESSMENT_EXPIRATION_MILLIS, Long.class);
				opinionN = config.get(Configuration.OPINION_N, Integer.class);
			}

			try {
				// retrieving assessments
				getAssessment = connection.prepareStatement(
						"SELECT * FROM assessments WHERE k=? AND ca=?");

				getAssessments = connection.prepareStatement(
						"SELECT * FROM assessments");

				getAssessmentsS = connection.prepareStatement(
						"SELECT * FROM certificates WHERE publickey=? AND subject=? AND S=1");

				// setting assessments
				setAssessment = new UpdateInsertStmnt(connection, "assessments",
						new String [] { "k", "?" }, new String [] { "ca", "?",
						"o_kl_t", "?", "o_kl_c", "?", "o_kl_f", "?",
						"o_kl_r", "?", "o_kl_s", "?",
						"o_it_ca_t", "?", "o_it_ca_c", "?", "o_it_ca_f", "?",
						"o_it_ca_r", "?", "o_it_ca_s", "?",
						"o_it_ee_t", "?", "o_it_ee_c", "?", "o_it_ee_f", "?",
						"o_it_ee_r", "?", "o_it_ee_s", "?",
						"timestamp", "?" });

				setAssessmentS = new UpdateInsertStmnt(connection, "certificates",
						new String [] { "serial", "?", "issuer", "?" }, new String [] {
						"subject", "?", "publickey", "?",
						"notbefore", "?", "notafter", "?", "certdata", "?",
						"revoked", "!0", "trusted", "!0", "untrusted", "!0", "S", "?" });

				setAssessmentValid = connection.prepareStatement(
						"UPDATE assessments SET timestamp=? WHERE k=? AND ca=?");

				// retrieving certificates
				getCertificate = connection.prepareStatement(
						"SELECT * FROM certificates WHERE serial=? AND issuer=?");

				getCertificates = connection.prepareStatement(
						"SELECT * FROM certificates");

				getCertificateTrust = connection.prepareStatement(
						"SELECT * FROM certificates WHERE trusted=? AND untrusted=?");

				// setting certificates
				setCertificateTrust = new UpdateInsertStmnt(connection, "certificates",
						new String [] { "serial", "?", "issuer", "?" }, new String [] {
						"subject", "?", "publickey", "?",
						"notbefore", "?", "notafter", "?", "certdata", "?",
						"revoked", "!0", "trusted", "?", "untrusted", "?", "S", "!0" });

				setCertificate = new UpdateInsertStmnt(connection, "certificates",
						new String [] { "serial", "?", "issuer", "?" }, new String [] {
						"subject", "?", "publickey", "?",
						"notbefore", "?", "notafter", "?", "certdata", "?",
						"revoked", "!0", "trusted", "!0", "untrusted", "!0", "S", "!0" });

				setCertificateRevoked = new UpdateInsertStmnt(connection, "certificates",
						new String [] { "serial", "?", "issuer", "?" }, new String [] {
						"subject", "?", "publickey", "?",
						"notbefore", "?", "notafter", "?", "certdata", "?",
						"revoked", "?", "trusted", "!0", "untrusted", "!0", "S", "!0" });

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

				// CRL
				addCRL = new UpdateInsertStmnt(connection, "crl",
							new String [] { "serial", "?", "issuer", "?", "urls", "?" },
							new String [] { "nextupdate", "?", "crldata", "?" });

				getCRL = connection.prepareStatement(
						"SELECT * FROM certificates JOIN crl " +
						"  ON certificates.serial = crl.serial" +
						"  AND certificates.issuer = crl.issuer" +
						"  WHERE crl.serial=? AND crl.issuer=? AND crl.urls=?");

				// OCSP
				addOCSP = new UpdateInsertStmnt(connection, "ocsp",
						new String [] { "serial", "?", "issuer", "?", "urls", "?" },
						new String [] { "nextupdate", "?" });

				getOCSP = connection.prepareStatement(
						"SELECT * FROM certificates JOIN ocsp " +
						"  ON certificates.serial = ocsp.serial" +
						"  AND certificates.issuer = ocsp.issuer" +
						"  WHERE ocsp.serial=? AND ocsp.issuer=? AND ocsp.urls=?");

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
				close();
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
				setAssessmentS.setBoolean(8, true);
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
			getAssessmentsS.setString(1, k);
			getAssessmentsS.setString(2, ca);
			try (ResultSet resultS = getAssessmentsS.executeQuery()) {
				while (resultS.next()) {
					setAssessmentS.setString(1, resultS.getString(1));
					setAssessmentS.setString(2, resultS.getString(2));
					setAssessmentS.setString(3, resultS.getString(3));
					setAssessmentS.setString(4, resultS.getString(4));
					setAssessmentS.setTimestamp(5, resultS.getTimestamp(5));
					setAssessmentS.setTimestamp(6, resultS.getTimestamp(6));
					setAssessmentS.setBytes(7, resultS.getBytes(7));
					setAssessmentS.setBoolean(8, false);
					setAssessmentS.executeUpdate();
				}
			}

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
	public boolean isCertificateTrusted(TrustCertificate certificate) {
		try {
			validateDatabaseConnection();
			getCertificate.setString(1, certificate.getSerial());
			getCertificate.setString(2, certificate.getIssuer());
			try (ResultSet result = getCertificate.executeQuery()) {
				if (result.next() && result.getBoolean(9))
					return true;
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
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
		}
		catch (SQLException | CertificateException e) {
			e.printStackTrace();
		}
		return certificates;
	}

	@Override
	public boolean isCertificateUntrusted(TrustCertificate certificate) {
		try {
			validateDatabaseConnection();
			getCertificate.setString(1, certificate.getSerial());
			getCertificate.setString(2, certificate.getIssuer());
			try (ResultSet result = getCertificate.executeQuery()) {
				if (result.next() && result.getBoolean(10))
					return true;
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public Collection<TrustCertificate> getAllCertificates() {
		Set<TrustCertificate> certificates = new HashSet<>();
		try {
			validateDatabaseConnection();
			try (ResultSet result = getCertificates.executeQuery()) {
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
	public boolean hasCertificate(TrustCertificate certificate) {
		try {
			validateDatabaseConnection();
			getCertificate.setString(1, certificate.getSerial());
			getCertificate.setString(2, certificate.getIssuer());
			try (ResultSet result = getCertificate.executeQuery()) {
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
	public void setRevokedCertificate(TrustCertificate certificate) {
		try {
			validateDatabaseConnection();
			setCertificateRevoked.setString(1, certificate.getSerial());
			setCertificateRevoked.setString(2, certificate.getIssuer());
			setCertificateRevoked.setString(3, certificate.getSubject());
			setCertificateRevoked.setString(4, certificate.getPublicKey());
			setCertificateRevoked.setTimestamp(5, new Timestamp(certificate.getNotBefore().getTime()));
			setCertificateRevoked.setTimestamp(6, new Timestamp(certificate.getNotAfter().getTime()));
			if (certificate.getCertificate() != null)
				setCertificateRevoked.setBytes(7, certificate.getCertificate().getEncoded());
			else
				setCertificateRevoked.setNull(7, Types.BLOB);
			setCertificateRevoked.setBoolean(8, true);
			setCertificateRevoked.executeUpdate();
		}
		catch (SQLException | CertificateEncodingException e) {
			e.printStackTrace();
		}
	}

	@Override
	public boolean isCertificateRevoked(TrustCertificate certificate) {
		try {
			validateDatabaseConnection();
			getCertificate.setString(1, certificate.getSerial());
			getCertificate.setString(2, certificate.getIssuer());
			try (ResultSet result = getCertificate.executeQuery()) {
				if (result.next() && result.getBoolean(8))
					return true;
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
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

			setCertificate.setString(1, certificate.getSerial());
			setCertificate.setString(2, certificate.getIssuer());
			setCertificate.setString(3, certificate.getSubject());
			setCertificate.setString(4, certificate.getPublicKey());
			setCertificate.setTimestamp(5, new Timestamp(certificate.getNotBefore().getTime()));
			setCertificate.setTimestamp(6, new Timestamp(certificate.getNotAfter().getTime()));
			if (certificate.getCertificate() != null)
				setCertificate.setBytes(7, certificate.getCertificate().getEncoded());
			else
				setCertificate.setNull(7, Types.BLOB);
			setCertificate.executeUpdate();

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
			validateDatabaseConnection();
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
			validateDatabaseConnection();
			getWatchlistCertificate.setString(1, certificate.getSerial());
			getWatchlistCertificate.setString(2, certificate.getIssuer());
			try (ResultSet result = getWatchlistCertificate.executeQuery()) {
				if (result.next())
					return result.getTimestamp(14);
			}
		}
		catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public void addCRL(CRLInfo crlInfo) {
		try {
			validateDatabaseConnection();
			TrustCertificate certificate = crlInfo.getCRLIssuer();

			setCertificate.setString(1, certificate.getSerial());
			setCertificate.setString(2, certificate.getIssuer());
			setCertificate.setString(3, certificate.getSubject());
			setCertificate.setString(4, certificate.getPublicKey());
			setCertificate.setTimestamp(5, new Timestamp(certificate.getNotBefore().getTime()));
			setCertificate.setTimestamp(6, new Timestamp(certificate.getNotAfter().getTime()));
			if (certificate.getCertificate() != null)
				setCertificate.setBytes(7, certificate.getCertificate().getEncoded());
			else
				setCertificate.setNull(7, Types.BLOB);
			setCertificate.executeUpdate();

			deferredCRLBatch.put(crlInfo, crlInfo);
		}
		catch (SQLException | CertificateException e) {
			e.printStackTrace();
		}
	}

	@Override
	public CRLInfo getCRL(CRLInfo crlInfo) {
		CRLInfo deferredCRLInfo = deferredCRLBatch.get(crlInfo);
		if (deferredCRLInfo != null)
			return deferredCRLInfo;

		try {
			validateDatabaseConnection();
			List<String> crlInfoURLs = new ArrayList<>(crlInfo.getURLs().size());
			for (URL url : crlInfo.getURLs())
				crlInfoURLs.add(url.toString());

			getCRL.setString(1, crlInfo.getCRLIssuer().getSerial());
			getCRL.setString(2, crlInfo.getCRLIssuer().getIssuer());
			getCRL.setString(3, serialize(crlInfoURLs));
			try (ResultSet result = getCRL.executeQuery()) {
				if (result.next()) {
					TrustCertificate crlIssuer = constructCertificate(result);

					List<String> strings = deserialize(result.getString(14));
					List<URL> urls = new ArrayList<>(strings.size());
					for (String string : strings)
						urls.add(new URL(string));

					Timestamp timestamp = result.getTimestamp(15);
					Option<Date> nextUpdate = !result.wasNull()
							? new Option<Date>(new Date(timestamp.getTime()))
							: new Option<Date>();

					byte[] blob = result.getBytes(16);
					Option<CRL> crl = !result.wasNull()
							? new Option<CRL>(
								CertificateFactory.getInstance("X.509").
									generateCRL(new ByteArrayInputStream(blob)))
							: new Option<CRL>();

					return new CRLInfo(crlIssuer, urls, nextUpdate, crl);
				}
			}
		}
		catch (SQLException | CertificateException | CRLException |
		       MalformedURLException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public void addOCSP(OCSPInfo ocspInfo) {
		try {
			validateDatabaseConnection();

			TrustCertificate certificate = ocspInfo.getCertificateIssuer();
			List<String> urls = new ArrayList<>(ocspInfo.getURLs().size());
			for (URL url : ocspInfo.getURLs())
				urls.add(url.toString());

			setCertificate.setString(1, certificate.getSerial());
			setCertificate.setString(2, certificate.getIssuer());
			setCertificate.setString(3, certificate.getSubject());
			setCertificate.setString(4, certificate.getPublicKey());
			setCertificate.setTimestamp(5, new Timestamp(certificate.getNotBefore().getTime()));
			setCertificate.setTimestamp(6, new Timestamp(certificate.getNotAfter().getTime()));
			if (certificate.getCertificate() != null)
				setCertificate.setBytes(7, certificate.getCertificate().getEncoded());
			else
				setCertificate.setNull(7, Types.BLOB);
			setCertificate.executeUpdate();

			addOCSP.setString(1, certificate.getSerial());
			addOCSP.setString(2, certificate.getIssuer());
			addOCSP.setString(3, serialize(urls));
			if (ocspInfo.getNextUpdate().isSet())
				addOCSP.setTimestamp(4, new Timestamp(ocspInfo.getNextUpdate().get().getTime()));
			else
				addOCSP.setNull(4, Types.TIMESTAMP);
			addOCSP.executeUpdate();
		}
		catch (SQLException | CertificateException e) {
			e.printStackTrace();
		}
	}

	@Override
	public OCSPInfo getOCSP(OCSPInfo ocspInfo) {
		try {
			validateDatabaseConnection();
			List<String> ocspInfoURLs = new ArrayList<>(ocspInfo.getURLs().size());
			for (URL url : ocspInfo.getURLs())
				ocspInfoURLs.add(url.toString());

			getOCSP.setString(1, ocspInfo.getCertificateIssuer().getSerial());
			getOCSP.setString(2, ocspInfo.getCertificateIssuer().getIssuer());
			getOCSP.setString(3, serialize(ocspInfoURLs));
			try (ResultSet result = getOCSP.executeQuery()) {
				if (result.next()) {
					TrustCertificate certificateIssuer = constructCertificate(result);

					List<String> strings = deserialize(result.getString(14));
					List<URL> urls = new ArrayList<>(strings.size());
					for (String string : strings)
						urls.add(new URL(string));

					Timestamp timestamp = result.getTimestamp(15);
					Option<Date> nextUpdate = !result.wasNull()
							? new Option<Date>(new Date(timestamp.getTime()))
							: new Option<Date>();

					return new OCSPInfo(certificateIssuer, urls, nextUpdate);
				}
			}
		}
		catch (SQLException | CertificateException | MalformedURLException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public void clean() {
		try {
			validateDatabaseConnection();
			final long nowMillis = new Date().getTime();

			// remove expired watchlist certificates
			try (ResultSet result = getWatchlistCertificates.executeQuery()) {
				while (result.next())
					if (nowMillis - result.getTimestamp(14).getTime()
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
								setAssessmentS.setTimestamp(5, resultS.getTimestamp(5));
								setAssessmentS.setTimestamp(6, resultS.getTimestamp(6));
								setAssessmentS.setBytes(7, resultS.getBytes(7));
								setAssessmentS.setBoolean(8, false);
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
	public void notify(Notification notification) {
		notifications.add(notification);
	}

	@Override
	public void save() throws ModelAccessException {
		try {
			if (!deferredCRLBatch.isEmpty()) {
				// execute statements that update the CRL table as last
				// statements of the transaction because it is much faster
				validateDatabaseConnection();
				for (CRLInfo crlInfo : deferredCRLBatch.values())
					try {
						TrustCertificate certificate = crlInfo.getCRLIssuer();
						List<String> urls = new ArrayList<>(crlInfo.getURLs().size());
						for (URL url : crlInfo.getURLs())
							urls.add(url.toString());

						addCRL.setString(1, certificate.getSerial());
						addCRL.setString(2, certificate.getIssuer());
						addCRL.setString(3, serialize(urls));
						if (crlInfo.getNextUpdate().isSet())
							addCRL.setTimestamp(4, new Timestamp(crlInfo.getNextUpdate().get().getTime()));
						else
							addCRL.setNull(4, Types.TIMESTAMP);
						if (crlInfo.getCRL().isSet() && crlInfo.getCRL().get() instanceof X509CRL)
							addCRL.setBytes(5, ((X509CRL) crlInfo.getCRL().get()).getEncoded());
						else
							addCRL.setNull(5, Types.BLOB);
						addCRL.executeUpdate();
					}
					catch (SQLException | CRLException e) {
						e.printStackTrace();
					}
				deferredCRLBatch.clear();
			}

			connection.commit();

			for (Notification notification : notifications)
				notification.saved();
		}
		catch (SQLException e) {
			throw new ModelAccessException(e);
		}
		finally {
			close();
		}
	}

	@Override
	public void close() throws ModelAccessException {
		try {
			try {
				getAssessment.close();
				getAssessments.close();
				getAssessmentsS.close();
				setAssessment.close();
				setAssessmentS.close();
				setAssessmentValid.close();
				getCertificate.close();
				getCertificates.close();
				getCertificateTrust.close();
				setCertificateTrust.close();
				setCertificateRevoked.close();
				setCertificate.close();
				getCertificatesForHost.close();
				addCertificateToHost.close();
				addCertificateToWatchlist.close();
				removeCertificateFromWatchlist.close();
				getWatchlistCertificate.close();
				getWatchlistCertificates.close();
				addCRL.close();
				getCRL.close();
				addOCSP.close();
				getOCSP.close();
				removeAssessment.close();
				removeCertificate.close();
				cleanCertificates.close();
				eraseAssessments.close();
				eraseCertificates.close();
			}
			finally {
				if (!connection.isClosed()) {
					connection.rollback();
					connection.close();
				}
			}
		}
		catch (SQLException e) {
			throw new ModelAccessException(e);
		}
	}

	static private String serialize(List<String> strings) {
		StringBuilder builder = new StringBuilder();
		boolean first = true;

		for (String string : strings) {
			if (first)
				first = false;
			else
				builder.append('|');

			for (int i = 0, l = string.length(); i < l; i++) {
				char ch = string.charAt(i);
				if (ch == '|' || ch == '^')
					builder.append('^');
				builder.append(ch);
			}
		}

		return builder.toString();
	}

	static private List<String> deserialize(String string) {
		StringBuilder builder = new StringBuilder();
		List<String> strings = new ArrayList<>();
		boolean escaped = false;

		for (int i = 0, l = string.length(); i < l; i++) {
			char ch = string.charAt(i);
			if (ch == '|') {
				if (!escaped) {
					strings.add(builder.toString());
					builder.delete(0, builder.length());
				}
				else {
					builder.append('|');
					escaped = false;
				}
			}
			else if (ch == '^') {
				if (escaped)
					builder.append('^');
				escaped = !escaped;
			}
			else
				builder.append(ch);
		}

		strings.add(builder.toString());
		return strings;
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
