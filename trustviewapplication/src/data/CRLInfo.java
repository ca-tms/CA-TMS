package data;

import java.net.URL;
import java.security.cert.CRL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import util.Option;

/**
 * Represents access information to Certificate Revocation Lists
 */
public class CRLInfo {
	private final TrustCertificate crlIssuer;
	private final List<URL> urls;
	private final Option<Date> nextUpdate;
	private final Option<CRL> crl;

	/**
	 * Creates a new <code>CRLInfo</code> instance
	 * @param crlIssuer the issuer of the CRL
	 * @param urls the URLs where the CRL can be retrieved from
	 * @param nextUpdate the next update date for the CRL if available
	 * @param crl the CRL data if available
	 */
	public CRLInfo(TrustCertificate crlIssuer, List<URL> urls,
			Option<Date> nextUpdate, Option<? extends CRL> crl) {
		this.crlIssuer = crlIssuer;
		this.urls = Collections.unmodifiableList(new ArrayList<>(urls));
		this.nextUpdate = nextUpdate;
		this.crl = crl.isSet() ? new Option<CRL>(crl.get()) : new Option<CRL>();
	}

	/**
	 * Creates a new <code>CRLInfo</code> instance
	 * @param crlIssuer the issuer of the CRL
	 * @param urls the URLs where the CRL can be retrieved from
	 */
	public CRLInfo(TrustCertificate crlIssuer, List<URL> urls) {
		this.crlIssuer = crlIssuer;
		this.urls = Collections.unmodifiableList(new ArrayList<>(urls));
		this.nextUpdate = new Option<>();
		this.crl = new Option<>();
	}
	/**
	 * @return the issuer of the CRL
	 */
	public TrustCertificate getCRLIssuer() {
		return crlIssuer;
	}

	/**
	 * @return the URLs where the CRL can be retrieved from
	 */
	public List<URL> getURLs() {
		return urls;
	}

	/**
	 * @return the next update date for the CRL if available
	 */
	public Option<Date> getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * @return the CRL data if available
	 */
	public Option<CRL> getCRL() {
		return crl;
	}

	/**
	 * @return whether the given certificate has been revoked; will return
	 * <code>false</code> if the CRL data is not available
	 * @see #getCRL()
	 * @param certificate
	 */
	public boolean isRevoked(TrustCertificate certificate) {
		if (!crl.isSet())
			return false;
		if (certificate.getCertificate() == null)
			return true;
		return crl.get().isRevoked(certificate.getCertificate());
	}

	@Override
	public int hashCode() {
		return 31 * crlIssuer.hashCode() + urls.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		CRLInfo other = (CRLInfo) obj;
		return crlIssuer.equals(other.getCRLIssuer()) &&
		       urls.equals(other.getURLs());
	}
}
