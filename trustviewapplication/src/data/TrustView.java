package data;

import java.util.Collection;
import java.util.Date;
import java.util.Map;

/**
 * <p>Provides access to the Trust View.
 * A Trust View stores the public key trust assessments, a set of trusted and
 * a set of untrusted certificates, as described in
 * <q>Trust views for the web pki</q> [1], section 4.2.</p>
 *
 * <p>A <code>TrustView</code> object must be closed after usage in order for
 * any modification made on the <code>TrustView</code> to take effect and
 * to release acquired resources.</p>
 *
 * <p>Closing the <code>TrustView</code> object may fail in case of concurrent
 * modifications.</p>
 *
 * <p>[1] Johannes Braun, Florian Volk, Johannes Buchmann, and Max Mühlhäuser.
 * Trust views for the web pki. 2013.</p>
 */
public interface TrustView extends AutoCloseable {
	/**
	 * @param S a certificate certifying a CA
	 *
	 * @return the {@link TrustAssessment} for the CA that is certified
	 * by the given certificate
	 */
	TrustAssessment getAssessment(TrustCertificate S);

	/**
	 * @param k public key for the given CA
	 * @param ca the CA which the public key belongs to
	 *
	 * @return the {@link TrustAssessment} for the given CA and its given
	 * public key
	 */
	TrustAssessment getAssessment(String k, String ca);

	/**
	 * Sets the given {@link TrustAssessment} by incorporating it into the
	 * <code>TrustView</code>, potentially overwriting a previous
	 * <code>TrustAssessment</code> for the same CA and public key.
	 *
	 * This also updates the internal assessment time stamp used
	 * when cleaning the trust view using {@link #clean()}.
	 *
	 * @param assessment the <code>TrustAssessment</code> to be set
	 */
	void setAssessment(TrustAssessment assessment);

	/**
	 * Sets the respective {@link TrustAssessment} to be still valid,
	 * if it already exists in the <code>TrustView</code>.
	 *
	 * This updates the internal assessment time stamp used
	 * when cleaning the trust view using {@link #clean()}.
	 *
	 * @param k public key for the given CA
	 * @param ca the CA which the public key belongs to
	 */
	void setAssessmentValid(String k, String ca);

	/**
	 * Removes the respective {@link TrustAssessment} from the
	 * <code>TrustView</code>
	 *
	 * @param k public key for the given CA
	 * @param ca the CA which the public key belongs to
	 */
	void removeAssessment(String k, String ca);

	/**
	 * @return a collection of all {@link TrustAssessment}s that are
	 * currently stored in the <code>TrustView</code>
	 */
	Collection<TrustAssessment> getAssessments();

	/**
	 * @return a collection of all trusted certificates that are
	 * currently stored in the <code>TrustView</code>
	 */
	Collection<TrustCertificate> getTrustedCertificates();

	/**
	 * @return a collection of all untrusted certificates that are
	 * currently stored in the <code>TrustView</code>
	 */
	Collection<TrustCertificate> getUntrustedCertificates();

	/**
	 * Sets the given certificate to be trusted
	 * @param S
	 */
	void setTrustedCertificate(TrustCertificate S);

	/**
	 * Sets the given certificate to be untrusted
	 * @param S
	 */
	void setUntrustedCertificate(TrustCertificate S);

	/**
	 * Removes the given (trusted or untrusted) certificate from the
	 * <code>TrustView</code>.
	 *
	 * This will not remove certificates in the S set of any
	 * {@link TrustAssessment}.
	 *
	 * @param S
	 */
	void removeCertificate(TrustCertificate S);

	/**
	 * @return a collection of all {@link TrustCertificate}s
	 * for the given host that were previously stored using
	 * {@link #addHostForCertificate(TrustCertificate, String)}
	 */
	Collection<TrustCertificate> getCertificatesForHost(String host);

	/**
	 * Adds a host for the given {@link TrustCertificate}
	 * that can later be retrieved using
	 * {@link #addCertificateToHost(TrustCertificate, String)};
	 * the method may fail if the <code>TrustView</code> does not contain
	 * the given certificate
	 * @param certificate
	 * @param host
	 */
	void addHostForCertificate(TrustCertificate certificate, String host);

	/**
	 * Adds a host for the given {@link TrustCertificate} to the watchlist
	 * @param certificate
	 */
	void addCertificateToWatchlist(TrustCertificate certificate);

	/**
	 * Removes the given {@link TrustCertificate} from the watchlist
	 * @param certificate
	 */
	void removeCertificateFromWatchlist(TrustCertificate certificate);

	/**
	 * @return whether the given certificate is currently on the watchlist
	 * @param certificate
	 */
	boolean isCertificateOnWatchlist(TrustCertificate certificate);

	/**
	 * Returns the current watchlist as a mapping from each
	 * {@link TrustCertificate} on the watchlist to the time the certificate was
	 * added to the watchlist
	 */
	Map<TrustCertificate, Date> getWatchlist();

	/**
	 * Cleans the trust view.
	 *
	 * This means all expired assessments will be removed
	 * (see {@link Configuration#ASSESSMENT_EXPIRATION_MILLIS})
	 * as well as all certificates that left their validity period.
	 */
	void clean();

	/**
	 * Erases all data stored in the trust view
	 */
	void erase();

	@Override
	void close() throws ModelAccessException;
}
