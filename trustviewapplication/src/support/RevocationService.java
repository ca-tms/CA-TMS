package support;

import java.util.Date;

import util.Option;
import data.CRLInfo;
import data.OCSPInfo;
import data.TrustCertificate;

/**
 * Represents an external revocation service
 */
public interface RevocationService {
	/**
	 * @return if the given certificate is revoked as determined by the external
	 * revocation service
	 * @param certificate
	 */
	boolean isRevoked(TrustCertificate certificate);

	/**
	 * Updates local information from the external revocation service. Services
	 * may perform live lookups each time {@link #isRevoked(TrustCertificate)}
	 * is called or perform local lookups on the data retrieved using this
	 * method. This method is implicitly called by the first invocation of
	 * {@link #isRevoked(TrustCertificate)} if it wasn't called already.
	 */
	void update();

	/**
	 * @return the next update date for the revocation service; the date may not
	 * be available as long as no revocation check was performed yet using
	 * {@link #isRevoked(TrustCertificate)}
	 */
	Option<Date> getNextUpdate();

	/**
	 * @return the revocation service information or <code>null</code> if the
	 * information cannot be represented by the given class; can be of type
	 * {@link CRLInfo} or {@link OCSPInfo}
	 * @param infoClass
	 */
	<T> T getInfo(Class<T> infoClass);
}