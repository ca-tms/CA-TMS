package support.revocation;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import util.Option;

import data.TrustCertificate;

/**
 * Represents an Online Certificate Status Protocol service point
 */
public class OCSP {
	private URL ocsp;
	private X509Certificate issuerCertificate;
	private Date nextUpdate;
	private int timeoutMillis;

	/**
	 * Creates a new <code>OCSP</code> instance for the OCSP service that can be
	 * reached under the given URL and is responsible for certificates issued by
	 * the issuer which the given certificate is issued for
	 * @param ocsp
	 * @param issuerCertificate
	 * @throws MalformedURLException
	 */
	public OCSP(String ocsp, TrustCertificate issuerCertificate)
			throws MalformedURLException {
		this(ocsp, issuerCertificate.getCertificate());
	}

	/**
	 * Creates a new <code>OCSP</code> instance for the OCSP service that can be
	 * reached under the given URL and is responsible for certificates issued by
	 * the issuer which the given certificate is issued for
	 * @param ocsp
	 * @param issuerCertificate
	 * @throws MalformedURLException
	 */
	public OCSP(String ocsp, Certificate issuerCertificate)
			throws MalformedURLException {
		this.timeoutMillis = -1;
		if (issuerCertificate instanceof X509Certificate) {
			this.ocsp = new URL(ocsp);
			this.issuerCertificate = (X509Certificate) issuerCertificate;
		}
		else
			throw new IllegalArgumentException("given certificate is no X.509 certificate");
	}

	/**
	 * Creates a new <code>OCSP</code> instance for the OCSP service that can be
	 * reached under the given URL and is responsible for certificates issued by
	 * the issuer which the given certificate is issued for;
	 * uses the given timeout for OCSP requests triggered by
	 * {@link #isRevoked(TrustCertificate)} or {@link #isRevoked(Certificate)}
	 * @param ocsp
	 * @param issuerCertificate
	 * @param timeoutMillis
	 * @throws MalformedURLException
	 */
	public OCSP(String ocsp, TrustCertificate issuerCertificate, int timeoutMillis)
			throws MalformedURLException {
		this(ocsp, issuerCertificate.getCertificate());
		this.timeoutMillis = timeoutMillis;
	}

	/**
	 * Creates a new <code>OCSP</code> instance for the OCSP service that can be
	 * reached under the given URL and is responsible for certificates issued by
	 * the issuer which the given certificate is issued for;
	 * uses the given timeout for OCSP requests triggered by
	 * {@link #isRevoked(TrustCertificate)} or {@link #isRevoked(Certificate)}
	 * @param ocsp
	 * @param issuerCertificate
	 * @param timeoutMillis
	 * @throws MalformedURLException
	 */
	public OCSP(String ocsp, Certificate issuerCertificate, int timeoutMillis)
			throws MalformedURLException {
		this(ocsp, issuerCertificate);
		this.timeoutMillis = timeoutMillis;
	}

	/**
	 * @return whether the given certificate has been revoked
	 * @param certificate
	 * @throws IOException if the OCSP response cannot be retrieved
	 * @throws SocketTimeoutException if the connection times out
	 * @throws GeneralSecurityException if the OCSP cannot be verified
	 */
	public boolean isRevoked(TrustCertificate certificate)
			throws IOException, GeneralSecurityException {
		if (certificate.getCertificate() != null)
			return isRevoked(certificate.getCertificate());
		return true;
	}

	/**
	 * @return whether the given certificate has been revoked
	 * @param certificate
	 * @throws IOException if the OCSP response cannot be retrieved
	 * @throws SocketTimeoutException if the connection times out
	 * @throws GeneralSecurityException if the OCSP cannot be verified
	 */
	public boolean isRevoked(Certificate certificate)
			throws IOException, GeneralSecurityException {
		if (certificate instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) certificate;

			OCSPRequest ocspRequest = generateOCSPRequest(x509cert, issuerCertificate);
			OCSPResponse ocspResponse = performOCSPRequest(ocsp, ocspRequest, timeoutMillis);
			Response response = processOCSPResponse(ocspResponse, issuerCertificate);

			nextUpdate = response.nextUpdate;
			return response.isRevoked;
		}
		return false;
	}

	/**
	 * @return the next update date for the OCSP service; the date is not
	 * available as long as no revocation check was performed yet using
	 * {@link #isRevoked(TrustCertificate)} or {@link #isRevoked(Certificate)}
	 */
	public Option<Date> getNextUpdate() {
		return nextUpdate != null ? new Option<Date>(nextUpdate) : new Option<Date>();
	}

	/**
	 * Represents an OCSP response result
	 */
	private static final class Response {
		public final boolean isRevoked;
		public final Date nextUpdate;

		public Response(boolean isRevoked, Date nextUpdate) {
			this.isRevoked = isRevoked;
			this.nextUpdate = nextUpdate;
		}
	}

	/**
	 * @return an OCSP request for the given certificate that was issued by
	 * the issuer which the given issuer certificate is issued for
	 * @param certificate
	 * @param issuerCertificate
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	private static OCSPRequest generateOCSPRequest(
			X509Certificate certificate, X509Certificate issuerCertificate)
					throws IOException, GeneralSecurityException {
		MessageDigest digest = MessageDigest.getInstance("SHA1");
		AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(
				new ASN1ObjectIdentifier(OIWObjectIdentifiers.idSHA1.getId()));

		if (!issuerCertificate.getSubjectX500Principal().equals(
				certificate.getIssuerX500Principal()))
			throw new CertificateException("Issuing cerrtificate and issued certificate mismatch");

		// issuer hash
		digest.update(issuerCertificate.getSubjectX500Principal().getEncoded());
		ASN1OctetString issuerNameHash = new DEROctetString(digest.digest());

		// issuer public key hash
		SubjectPublicKeyInfo publicKey = SubjectPublicKeyInfo.getInstance(
				parseASN1(issuerCertificate.getPublicKey().getEncoded()));
		digest.update(publicKey.getPublicKeyData().getBytes());
		ASN1OctetString issuerKeyHash = new DEROctetString(digest.digest());

		// certificate serial number
		ASN1Integer serialNumber = new ASN1Integer(certificate.getSerialNumber());

		// OCSP request
		CertID certID = new CertID(
				digestAlgorithm, issuerNameHash, issuerKeyHash, serialNumber);
		ASN1Sequence requestList = new DERSequence(new Request(certID, null));
		TBSRequest request = new TBSRequest(null, requestList, (Extensions) null);

		return new OCSPRequest(request, null);
	}

	/**
	 * Performs the given OCSP request to the given URL
	 * @return the received OCSP response
	 * @param url
	 * @param request
	 * @throws IOException
	 * @throws SocketTimeoutException
	 */
	private static OCSPResponse performOCSPRequest(
			URL url, OCSPRequest request, int timeoutMillis) throws IOException {
		try {
			// setup connection
			URLConnection connection = url.openConnection();
			if (timeoutMillis >= 0) {
				connection.setConnectTimeout(timeoutMillis);
				connection.setReadTimeout(timeoutMillis);
			}
			connection.setRequestProperty("Content-Type", "application/ocsp-request");
			connection.setRequestProperty("Accept", "application/ocsp-response");
			connection.setDoOutput(true);

			// send request
			try (OutputStream stream = connection.getOutputStream();
			     BufferedOutputStream bufferedStream = new BufferedOutputStream(stream);
			     DataOutputStream dataStream = new DataOutputStream(bufferedStream)) {
				dataStream.write(request.getEncoded());
			}

			// process HTTP ststus code
			if (connection instanceof HttpURLConnection &&
					((HttpURLConnection) connection).getResponseCode() / 100 != 2)
				throw new FileNotFoundException(url.toString());

			// receive response
			try (InputStream stream = connection.getInputStream();
			     BufferedInputStream bufferedStream = new BufferedInputStream(stream);
			     ASN1InputStream asn1stream = new ASN1InputStream(bufferedStream)) {
				return OCSPResponse.getInstance(asn1stream.readObject());
			}
		}
		catch (ClassCastException | IllegalArgumentException e) {
			throw new IOException(e);
		}
	}

	/**
	 * Processes the given OCSP response for a certificate that was issued by
	 * the issuer which the given issuer certificate is issued for
	 * @return the parsed OCSP result
	 * @param response
	 * @param issuerCertificate
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	private static Response processOCSPResponse(OCSPResponse response,
			X509Certificate issuerCertificate)
					throws IOException, GeneralSecurityException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");

		try {
			if (response.getResponseBytes() == null)
				return new Response(false, null);

			// create basic response object
			BasicOCSPResponse basicResponse = BasicOCSPResponse.getInstance(
					parseASN1(response.getResponseBytes().getResponse()));

			// create signature object
			// is creating signatures from OIDs a well-defined process?
			String algorithm =
					basicResponse.getSignatureAlgorithm().getAlgorithm().getId();
			Signature signature = Signature.getInstance(algorithm);

			// set signature algorithm parameters
			ASN1Encodable encodableParams = basicResponse.getSignatureAlgorithm().getParameters();
			if (encodableParams != null &&
					!encodableParams.equals(org.bouncycastle.asn1.DERNull.INSTANCE)) {

				ASN1Primitive primitiveParams = encodableParams.toASN1Primitive();
				if (primitiveParams != null &&
						!primitiveParams.equals(org.bouncycastle.asn1.DERNull.INSTANCE)) {

					AlgorithmParameters params =
							AlgorithmParameters.getInstance(algorithm);
					params.init(primitiveParams.getEncoded());

					signature.setParameter(
							params.getParameterSpec(AlgorithmParameterSpec.class));
				}
			}

			// validate and use the certificate supplied by the OCSP response
			// where necessary
			ASN1Sequence certs = basicResponse.getCerts();
			if (certs != null &&
					!certs.equals(org.bouncycastle.asn1.DERNull.INSTANCE)) {

				List<X509Certificate> certList = new ArrayList<>();
				for (int i = 0; i < certs.size(); i++) {
					X509Certificate cert =
							(X509Certificate) factory.generateCertificate(
								new ByteArrayInputStream(
									certs.getObjectAt(0).toASN1Primitive().getEncoded()));
					cert.checkValidity();
					certList.add(cert);
				}

				CertPath path = factory.generateCertPath(certList);
				PKIXParameters params = new PKIXParameters(
						Collections.singleton(
								new TrustAnchor(issuerCertificate, null)));
				params.setRevocationEnabled(false);
				CertPathValidator validator = CertPathValidator.getInstance("PKIX");
				PKIXCertPathValidatorResult result =
						(PKIXCertPathValidatorResult) validator.validate(path, params);

				if (result.getTrustAnchor().getTrustedCert() == null)
					throw new CertPathValidatorException(
						"Validation failed for certificate supplied by OCSP response",
						null, path, -1, PKIXReason.NO_TRUST_ANCHOR);

			    issuerCertificate = certList.get(0);
			}

			// verify OCSP response signature
			signature.initVerify(issuerCertificate.getPublicKey());
			signature.update(basicResponse.getTbsResponseData().getEncoded());
			if (!signature.verify(basicResponse.getSignature().getBytes()))
				throw new SignatureException("OCSP signature verification failed");

			// process response
			ASN1Sequence responses = basicResponse.getTbsResponseData().getResponses();
			if (responses.size() != 1)
				throw new GeneralSecurityException("OCSP response mismatch");
			SingleResponse singleResponse = SingleResponse.getInstance(
					responses.getObjectAt(0));

			// single response choices
			//   good        [0]     IMPLICIT NULL
			//   revoked     [1]     IMPLICIT RevokedInfo
			//   unknown     [2]     IMPLICIT UnknownInfo
			return new Response(
					singleResponse.getCertStatus().getTagNo() == 1,
					singleResponse.getNextUpdate() != null
						? singleResponse.getNextUpdate().getDate()
						: null);
		}
		catch (ClassCastException | IllegalArgumentException | ParseException e) {
			throw new IOException(e);
		}
	}

	/**
	 * @return the parsed encoded ASN1 structure
	 * @param octets
	 * @throws IOException
	 */
	private static ASN1Primitive parseASN1(byte[] octets) throws IOException {
		try (ByteArrayInputStream octetStream = new ByteArrayInputStream(octets);
		     ASN1InputStream asn1stream = new ASN1InputStream(octetStream)) {
			return asn1stream.readObject();
		}
	}

	/**
	 * @return the parsed encoded ASN1 structure
	 * @param octets
	 * @throws IOException
	 */
	private static ASN1Primitive parseASN1(ASN1OctetString octets) throws IOException {
		try (InputStream octetStream = octets.getOctetStream();
		     ASN1InputStream asn1stream = new ASN1InputStream(octetStream)) {
			return asn1stream.readObject();
		}
	}
}
