package data;

import java.util.Collection;

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
	 * <code>TrustAssessment</code> for the same CA and public key
	 * @param assessment the <code>TrustAssessment</code> to be set
	 */
	void setAssessment(TrustAssessment assessment);

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
	 * Cleans the trust view
	 */
	void clean();
}
