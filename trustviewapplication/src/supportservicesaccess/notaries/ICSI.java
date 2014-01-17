package supportservicesaccess.notaries;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Formatter;

/**
 * This class provides access to the ICSI notary service.
 * http://notary.icsi.berkeley.edu/
 */
public class ICSI extends Notary {
	
	public ICSI() {
		// nothing to do here
	}

	@Override
	public int queryNotary(X509Certificate cert) {
		
		//String hash = sha1FromCert(cert);
		//String requestURL = hash + ".notary.icsi.berkeley.edu";
		
		// TODO implement
		return Notary.UNKNOWN;
	}
	
	/**
	 * Compute SHA-1 hash of certificate.
	 * @param cert the certificate to hash
	 * @return the hash value in hex string format
	 */
	private String sha1FromCert(X509Certificate cert) {
		try {
			byte[] rawCert = cert.getTBSCertificate();
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
