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
}
