package supportservicesaccess.notaries;

import java.security.cert.X509Certificate;

/**
 * This class represents an abstract notary service and defines the required interface.
 */
public abstract class Notary {

	public final static int UNTRUSTED = -1;
	public final static int UNKNOWN = 0;
	public final static int TRUSTED = 1;
	
	/**
	 * Query the notary service.
	 * @param cert the certificate to validate by the notary
	 * @return the validation result as an integer, according to the defined constants
	 */
	public abstract int queryNotary(X509Certificate cert);
	
}
