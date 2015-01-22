package support.revocation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import data.TrustCertificate;

/**
 * Provides access to the revocation service locations defined in a
 * {@link TrustCertificate} or {@link Certificate}
 */
public class RevocationInfo {
	private List<String> ocsp = new ArrayList<>();
	private List<String> crl = new ArrayList<>();
	private List<Byte> subjectKeyIdentifier = null;
	private List<Byte> authorityKeyIdentifier = null;
	private String authoritySerial = null;

	/**
	 * Creates a new <code>RevocationInfo</code> instance  based on the given
	 * certificate
	 * @param certificate
	 */
	public RevocationInfo(TrustCertificate certificate) {
		this(certificate.getCertificate());
	}

	/**
	 * Creates a new <code>RevocationInfo</code> instance based on the given
	 * certificate
	 * @param certificate
	 */
	public RevocationInfo(Certificate certificate) {
	    if (certificate instanceof X509Certificate)
	    	try {
				X509Certificate x509cert = (X509Certificate) certificate;

				// process Authority Information Access extension
				// to determine OCSP services
				AuthorityInformationAccess info = AuthorityInformationAccess.getInstance(
						certificateExtension(x509cert, Extension.authorityInfoAccess.getId()));

				if (info != null)
					for (AccessDescription desc : info.getAccessDescriptions())
						if (desc.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
							String url = urlFromGeneralName(desc.getAccessLocation());
							if (url != null)
								ocsp.add(url);
						}

				ocsp = Collections.unmodifiableList(ocsp);

				// process CRL Distribution Points extension
				// to determine CRL services
				CRLDistPoint points = CRLDistPoint.getInstance(
						certificateExtension(x509cert, Extension.cRLDistributionPoints.getId()));

				if (points != null)
					for (DistributionPoint point : points.getDistributionPoints()) {
						// no support for CRLs issued from another CA
						GeneralNames crlIssuer = point.getCRLIssuer();
						if (crlIssuer != null && !crlIssuer.equals(DERNull.INSTANCE))
							continue;

						// no support for partial CRLs
						ReasonFlags reasons = point.getReasons();
						if (reasons != null && !reasons.equals(DERNull.INSTANCE))
							continue;

						// use all distribution points
						ASN1Encodable names = point.getDistributionPoint().getName();
						if (names instanceof GeneralNames)
							for (GeneralName name : ((GeneralNames) names).getNames()) {
								String url = urlFromGeneralName(name);
								if (url != null)
									crl.add(url);
							}
					}

				crl = Collections.unmodifiableList(crl);

				// Authority Key Identifier
				AuthorityKeyIdentifier authorityKeyId = AuthorityKeyIdentifier.getInstance(
						certificateExtension(x509cert, Extension.authorityKeyIdentifier.getId()));

				if (authorityKeyId != null) {
					byte[] keyidentifier = authorityKeyId.getKeyIdentifier();
					if (keyidentifier != null) {
						authorityKeyIdentifier = new ArrayList<>(keyidentifier.length);
						for (byte value : keyidentifier)
							authorityKeyIdentifier.add(value);
						authorityKeyIdentifier = Collections.unmodifiableList(authorityKeyIdentifier);
					}

					BigInteger serial = authorityKeyId.getAuthorityCertSerialNumber();
					if (serial != null)
						authoritySerial = serial.toString();
				}

				// Subject Key Identifier
				SubjectKeyIdentifier subjectKeyId = SubjectKeyIdentifier.getInstance(
						certificateExtension(x509cert, Extension.subjectKeyIdentifier.getId()));

				if (subjectKeyId != null) {
					byte[] keyidentifier = subjectKeyId.getKeyIdentifier();
					if (keyidentifier != null) {
						subjectKeyIdentifier = new ArrayList<>(keyidentifier.length);
						for (byte value : keyidentifier)
							subjectKeyIdentifier.add(value);
						subjectKeyIdentifier = Collections.unmodifiableList(subjectKeyIdentifier);
					}
				}

			}
			catch (ClassCastException | IllegalArgumentException e) {
				e.printStackTrace();
			}
	}

	/**
	 * @return the OCSP services
	 */
	public List<String> getOCSP() {
		return ocsp;
	}

	/**
	 * @return the CRL services
	 */
	public List<String> getCRL() {
		return crl;
	}

	/**
	 * @return the subject key identifier or <code>null</code> if not available
	 */
	public List<Byte> getSubjectKeyIdentifier() {
		return subjectKeyIdentifier;
	}

	/**
	 * @return the authority key identifier or <code>null</code> if not available
	 */
	public List<Byte> getAuthorityKeyIdentifier() {
		return authorityKeyIdentifier;
	}

	/**
	 * @return the authority serial number or <code>null</code> if not available
	 */
	public String getAuthoritySerial() {
		return authoritySerial;
	}

	/**
	 * @return the URI for the given name if the name represents a URI,
	 * otherwise <code>null</code>
	 * @param name
	 */
	private static String urlFromGeneralName(GeneralName name) {
		if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
			return ((ASN1String) name.getName()).getString();
		return null;
	}

	/**
	 * @return the parsed X.509 certificate extension with the specified OID for
	 * the given certificate
	 * @param certificate
	 * @param oid
	 */
	private static ASN1Primitive certificateExtension(
			X509Certificate certificate, String oid) {
		byte[] value = certificate.getExtensionValue(oid);
		ASN1OctetString octetString;

		if (value != null)
			try {
				try (ByteArrayInputStream valueStream = new ByteArrayInputStream(value);
					 ASN1InputStream asn1stream = new ASN1InputStream(valueStream)) {
					octetString = (ASN1OctetString) asn1stream.readObject();
				}

				try (InputStream octetStream = octetString.getOctetStream();
					 ASN1InputStream asn1stream = new ASN1InputStream(octetStream)) {
					return asn1stream.readObject();
				}
			}
			catch(IOException e) {
				e.printStackTrace();
			}

		return null;
	}
}
