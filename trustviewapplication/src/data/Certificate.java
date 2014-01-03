package data;

import java.security.Principal;
import java.security.cert.X509Certificate;

public abstract class Certificate {
	public abstract Principal getIssuer();
	public abstract Principal getSubject();

	public static Certificate fromX509Certificate(X509Certificate cert) {
		final Principal issuer = cert.getIssuerDN();
		final Principal subject = cert.getSubjectDN();

		return new Certificate() {
			@Override
			public Principal getIssuer() {
				return issuer;
			}

			@Override
			public Principal getSubject() {
				return subject;
			}

			@Override
			public int hashCode() {
				return 31 * issuer.hashCode() + subject.hashCode();
			}

			@Override
			public boolean equals(Object obj) {
				if (this == obj)
					return true;
				if (obj == null)
					return false;
				if (getClass() != obj.getClass())
					return false;
				Certificate other = (Certificate) obj;
				if (!issuer.equals(other.getIssuer()))
					return false;
				if (!subject.equals(other.getSubject()))
					return false;
				return true;
			}
		};
	}
}
