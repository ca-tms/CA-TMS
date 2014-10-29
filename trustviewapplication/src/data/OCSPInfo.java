package data;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import util.Option;

/**
 * Represents access information to OCSP services for a certificate issuer
 */
public class OCSPInfo {
	private final TrustCertificate certificateIssuer;
	private final List<URL> urls;
	private final Option<Date> nextUpdate;

	/**
	 * Creates a new <code>OCSPInfo</code> instance
	 * @param certificateIssuer the issuer of the certificates to be checked
	 * @param urls the URLs where the OSCP services can be reached
	 * @param nextUpdate the next update date for the OCSP service if available
	 */
	public OCSPInfo(TrustCertificate certificateIssuer, List<URL> urls,
			Option<Date> nextUpdate) {
		this.certificateIssuer = certificateIssuer;
		this.urls = Collections.unmodifiableList(new ArrayList<>(urls));
		this.nextUpdate = nextUpdate;
	}

	/**
	 * @return the issuer of the certificates to be checked
	 */
	public TrustCertificate getCertificateIssuer() {
		return certificateIssuer;
	}

	/**
	 * @return the URLs where the OSCP services can be reached
	 */
	public List<URL> getURLs() {
		return urls;
	}

	/**
	 * @return the next update date for the OCSP service if available
	 */
	public Option<Date> getNextUpdate() {
		return nextUpdate;
	}
}
