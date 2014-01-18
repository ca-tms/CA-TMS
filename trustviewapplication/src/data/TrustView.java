package data;

import java.util.Collection;

public interface TrustView extends AutoCloseable {
	TrustAssessment getAssessment(TrustCertificate S);
	TrustAssessment getAssessment(String k, String ca);
	void setAssessment(TrustAssessment assessment);
	Collection<TrustAssessment> getAssessments();
	Collection<TrustCertificate> getTrustedCertificates();
	Collection<TrustCertificate> getUntrustedCertificates();
	void setTrustedCertificate(TrustCertificate S);
	void setUntrustedCertificate(TrustCertificate S);
	void save() throws Exception;
}
