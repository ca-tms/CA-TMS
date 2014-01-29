package support.notaries;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.Certificate;
import java.util.Formatter;

import util.ValidationResult;

/**
 * This class provides access to the ICSI notary service.
 * http://notary.icsi.berkeley.edu/
 */
public class ICSI implements Notary {

	public ICSI() {
		// nothing to do here
	}

	@Override
	public ValidationResult queryNotary(Certificate cert) {

		String hash = sha1FromCert(cert);
		String requestURL = hash + ".notary.icsi.berkeley.edu";
		
		try {
			InetAddress address = InetAddress.getByName(requestURL);
			if(address.getHostAddress().equals("127.0.0.2")))
			return ValidationResult.TRUSTED;
			else
				return ValidationResult.UNTRUSTED;
			}
			catch(UnknownHostException uhe) {
			return ValidationResult.UNTRUSTED;
			}

	}

	/**
	 * Compute SHA-1 hash of certificate.
	 * @param cert the certificate to hash
	 * @return the hash value in hex string format
	 */
	private String sha1FromCert(Certificate cert) {
		try {
			byte[] rawCert = cert.getEncoded();
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			byte[] rawHash = md.digest(rawCert);
			Formatter formatter = new Formatter();
			for(byte b : rawHash) {
				formatter.format("%02x", b);
			}
			String hash = formatter.toString();
			formatter.close();
			return hash;
		} catch (CertificateEncodingException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
}
