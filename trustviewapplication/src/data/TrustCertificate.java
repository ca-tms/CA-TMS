package data;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

/**
 * Represents a certificate as used by the CA Trust Management System
 * abstracting over the underlying {@link Certificate} implementation
 * (which has to be {@link X509Certificate})
 */
public class TrustCertificate {
	private final String serial;
	private final String issuer;
	private final String subject;
	private final String publicKey;
	private final Date notBefore;
	private final Date notAfter;
	private final Certificate certificate;

	/**
	 * Creates a new <code>Certificate</code> initializing it with all data that
	 * is needed for a certificate in the CA Trust Management System
	 */
	public TrustCertificate(String serial, String issuer, String subject,
			String publicKey, Date notBefore, Date notAfter) {
		this.serial = serial;
		this.issuer = issuer;
		this.subject = subject;
		this.publicKey = publicKey;
		this.notBefore = notBefore;
		this.notAfter = notAfter;
		this.certificate = null;
	}

	/**
	 * Creates a new <code>Certificate</code> initializing it with all data that
	 * is needed for a certificate in the CA Trust Management System
	 * based on the given {@link Certificate} instance which can later be
	 * accessed using {@link #getCertificate()}
	 */
	public TrustCertificate(Certificate certificate) {
		if (certificate instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) certificate;

			this.serial = x509cert.getSerialNumber().toString();
			this.issuer = x509cert.getIssuerX500Principal().getName(
					X500Principal.CANONICAL);
			this.subject = x509cert.getSubjectX500Principal().getName(
					X500Principal.CANONICAL);
			this.publicKey = DatatypeConverter.printBase64Binary(
					x509cert.getPublicKey().getEncoded());
			this.notBefore = x509cert.getNotBefore();
			this.notAfter = x509cert.getNotAfter();
			this.certificate = x509cert;
		}
		else
			throw new UnsupportedOperationException(
					"Cannot create a TrustCertificate from a " +
					certificate.getClass().getSimpleName());
	}

	/**
	 * @return the certificate serial number
	 */
	public String getSerial() {
		return serial;
	}

	/**
	 * @return the certificate issuer
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * @return the certificate subject
	 */
	public String getSubject() {
		return subject;
	}

	/**
	 * @return the encoded certificate public key
	 */
	public String getPublicKey() {
		return publicKey;
	}

	/**
	 * @return the date which before the certificate is not valid
	 */
	public Date getNotBefore() {
		return notBefore;
	}

	/**
	 * @return the date which after the certificate is not valid
	 */
	public Date getNotAfter() {
		return notAfter;
	}

	/**
	 * @return the underlying {@link Certificate} implementation;
	 * will return <code>null</code> if the <code>TrustCertificate</code>
	 * instance was not created using the {@link #TrustCertificate(Certificate)}
	 * constructor
	 */
	public Certificate getCertificate() {
		return certificate;
	}

	@Override
	public int hashCode() {
		return 29791 * serial.hashCode() + 961 * issuer.hashCode() +
				31 * subject.hashCode() + publicKey.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		TrustCertificate other = (TrustCertificate) obj;
		return serial.equals(other.getSerial()) &&
		       issuer.equals(other.getIssuer()) &&
		       subject.equals(other.getSubject()) &&
		       publicKey.equals(other.getPublicKey());
	}
}
