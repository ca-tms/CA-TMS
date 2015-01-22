package support;

import java.util.Date;

import util.Option;
import data.CRLInfo;
import data.OCSPInfo;
import data.TrustCertificate;

/**
 * Represents an external revocation service
 */
public interface RevocationService<RevocationInfo> {
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
	 * @return the revocation service information; {@link CRLInfo} or
	 * {@link OCSPInfo} are candidates for this information; calls to
	 * {@link #update()} or {@link #isRevoked(TrustCertificate)} may cause this
	 * method to return updated information
	 * @param infoClass
	 */
	RevocationInfo getInfo();
}