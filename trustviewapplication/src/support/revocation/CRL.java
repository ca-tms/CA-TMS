package support.revocation;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;

import util.Option;

import data.TrustCertificate;

/**
 * Represents a Certificate Revocation List
 */
public class CRL {
	private X509CRL crl;
	private X509Certificate issuerCertificate;

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * retrieved from the given URL and is issued by the issuer which the given
	 * certificate is issued for
	 * @param url
	 * @param issuerCertificate
	 * @throws IOException if the CRL cannot be read
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(URL url, TrustCertificate issuerCertificate)
			throws IOException, GeneralSecurityException {
		this(url, issuerCertificate.getCertificate());
	}

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * retrieved from the given URL and is issued by the issuer which the given
	 * certificate is issued for
	 * @param url
	 * @param issuerCertificate
	 * @throws IOException if the CRL cannot be read
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(URL url, Certificate issuerCertificate)
			throws IOException, GeneralSecurityException {
		try (InputStream stream = url.openStream();
			 BufferedInputStream bufferedStream = new BufferedInputStream(stream)) {
			initialize(bufferedStream, issuerCertificate);
		}
	}

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * retrieved from the given URL and is issued by the issuer which the given
	 * certificate is issued for; uses the given timeout for the download
	 * @param url
	 * @param issuerCertificate
	 * @param timeoutMillis
	 * @throws IOException if the CRL cannot be read
	 * @throws SocketTimeoutException if the connection times out
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(URL url, TrustCertificate issuerCertificate, int timeoutMillis)
			throws IOException, GeneralSecurityException {
		this(url, issuerCertificate.getCertificate(), timeoutMillis);
	}

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * retrieved from the given URL and is issued by the issuer which the given
	 * certificate is issued for; uses the given timeout for the download
	 * @param url
	 * @param issuerCertificate
	 * @param timeoutMillis
	 * @throws IOException if the CRL cannot be read
	 * @throws SocketTimeoutException if the connection times out
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(URL url, Certificate issuerCertificate, int timeoutMillis)
			throws IOException, GeneralSecurityException {
		URLConnection connection = url.openConnection();
		connection.setConnectTimeout(timeoutMillis);
		connection.setReadTimeout(timeoutMillis);
		try (InputStream stream = connection.getInputStream();
			 BufferedInputStream bufferedStream = new BufferedInputStream(stream)) {
			initialize(bufferedStream, issuerCertificate);
		}
	}

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * read from the given stream and is issued by the issuer which the given
	 * certificate is issued for
	 * @param stream
	 * @param issuerCertificate
	 * @throws IOException if the CRL cannot be read
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(InputStream stream, TrustCertificate issuerCertificate)
			throws IOException, GeneralSecurityException {
		this(stream, issuerCertificate.getCertificate());
	}

	/**
	 * Creates a new <code>CRL</code> instance based on the CRL that can be
	 * read from the given stream and is issued by the issuer which the given
	 * certificate is issued for
	 * @param stream
	 * @param issuerCertificate
	 * @throws IOException if the CRL cannot be read
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	public CRL(InputStream stream, Certificate issuerCertificate)
			throws IOException, GeneralSecurityException {
		initialize(stream, issuerCertificate);
	}

	/**
	 * Initializes the <code>CRL</code> instance based on the CRL that can be
	 * read from the given stream and is issued by the issuer which the given
	 * certificate is issued for
	 * @param stream
	 * @param issuerCertificate
	 * @throws IOException if the CRL cannot be read
	 * @throws GeneralSecurityException if the CRL cannot be verified
	 */
	private void initialize(InputStream stream, Certificate issuerCertificate)
			throws IOException, GeneralSecurityException {
		if (issuerCertificate instanceof X509Certificate)
			this.issuerCertificate = (X509Certificate) issuerCertificate;
		else
			throw new IllegalArgumentException("given certificate is no X.509 certificate");

		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		this.crl = (X509CRL) factory.generateCRL(stream);

		if (!verifyCRLSignature(this.crl, this.issuerCertificate))
			throw new SignatureException("CRL signature verification failed");
	}

	/**
	 * @return the next update date for the CRL
	 */
	public Option<Date> getNextUpdate() {
		return new Option<>(crl.getNextUpdate());
	}

	/**
	 * @return whether the given certificate has been revoked
	 * @param certificate
	 */
	public boolean isRevoked(TrustCertificate certificate) {
		if (certificate.getCertificate() != null)
			return isRevoked(certificate.getCertificate());
		return true;
	}

	/**
	 * @return whether the given certificate has been revoked
	 * @param certificate
	 */
	public boolean isRevoked(Certificate certificate) {
		return crl.isRevoked(certificate);
	}

	/**
	 * @return the underlying {@link X509CRL} object
	 */
	public X509CRL getCRL() {
		return crl;
	}

	/**
	 * @return whether the given CRL can be verified using the given issuer
	 * certificate
	 * @param crl
	 * @param issuerCertificate
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	private static boolean verifyCRLSignature(X509CRL crl,
			X509Certificate issuerCertificate)
					throws GeneralSecurityException, IOException {
		if (crl == null)
			return false;

		Signature signature = Signature.getInstance(crl.getSigAlgName());

		if (crl.getSigAlgParams() != null) {
			AlgorithmParameters params =
					AlgorithmParameters.getInstance(crl.getSigAlgName());
			params.init(crl.getSigAlgParams());

			signature.setParameter(
					params.getParameterSpec(AlgorithmParameterSpec.class));
		}

		signature.initVerify(issuerCertificate.getPublicKey());
		signature.update(crl.getTBSCertList());
		return signature.verify(crl.getSignature());
	}
}
