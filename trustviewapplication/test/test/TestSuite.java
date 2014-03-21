package test;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import org.junit.Test;

import support.ValidationService;
import util.Option;
import util.ValidationResult;

import CertainTrust.CertainTrust;
import buisness.TrustComputation;
import data.Configuration;
import data.TrustAssessment;
import data.TrustCertificate;
import data.TrustView;

public class TestSuite {
	static final double EPSILON = 1e-10;

	Date notBefore = new Date();
	Date notAfter = new Date();

	TrustCertificate RCA1_RCA1 = new TrustCertificate("01", "RCA1", "RCA1", "RCA1-Key", notBefore, notAfter);
	TrustCertificate RCA1_SCA1 = new TrustCertificate("02", "RCA1", "SCA1", "SCA1-Key", notBefore, notAfter);
	TrustCertificate RCA1_SCA2 = new TrustCertificate("03", "RCA1", "SCA2", "SCA2-Key", notBefore, notAfter);

	TrustCertificate RCA2_RCA2 = new TrustCertificate("11", "RCA2", "RCA2", "RCA2-Key", notBefore, notAfter);
	TrustCertificate RCA2_SCA3 = new TrustCertificate("12", "RCA2", "SCA3", "SCA3-Key", notBefore, notAfter);

	TrustCertificate SCA1_EE1 = new TrustCertificate("21", "SCA1", "EE1", "EE1-Key", notBefore, notAfter);

	TrustCertificate SCA2_SCA3 = new TrustCertificate("31", "SCA2", "SCA3", "SCA3-Key", notBefore, notAfter);
	TrustCertificate SCA2_EE2 = new TrustCertificate("32", "SCA2", "EE2", "EE2-Key", notBefore, notAfter);
	TrustCertificate SCA2_EE3 = new TrustCertificate("33", "SCA2", "EE3", "EE3-Key", notBefore, notAfter);

	TrustCertificate SCA3_EE4 = new TrustCertificate("41", "SCA3", "EE4", "EE4-Key", notBefore, notAfter);
	TrustCertificate SCA3_EE5 = new TrustCertificate("42", "SCA3", "EE5", "EE5-Key", notBefore, notAfter);

	ValidationService validation = new ValidationService() {
		@Override
		public ValidationResult query(TrustCertificate certificate) {
			return certificate == SCA2_EE3 || certificate == SCA3_EE4
					? ValidationResult.UNTRUSTED : ValidationResult.TRUSTED;
		}
	};

	public static void assertEqualsCert(TrustCertificate expected, TrustCertificate actual) {
		assertEquals(expected.getSerial(), actual.getSerial());
		assertEquals(expected.getIssuer(), actual.getIssuer());
		assertEquals(expected.getSubject(), actual.getSubject());
		assertEquals(expected.getPublicKey(), actual.getPublicKey());
	}

	@Test
	public void opinionValuesStorage() throws Exception {
		TrustAssessment actual;
		TrustAssessment expected = new TrustAssessment(
				"key", "ca",
				Collections.<TrustCertificate>emptySet(), new Option<CertainTrust>(),
				new CertainTrust(10), new CertainTrust(10));

		try (EmptyModel model = new EmptyModel()) {
			for (int i = 0; i < 20; i++) {
				try (TrustView trustView = model.openTrustView()) {
					trustView.setAssessment(expected);
				}

				try (TrustView trustView = model.openTrustView()) {
					actual = trustView.getAssessment("key", "ca");
				}

				assertEquals(expected.getO_it_ca().getT(), actual.getO_it_ca().getT(), EPSILON);
				assertEquals(expected.getO_it_ca().getC(), actual.getO_it_ca().getC(), EPSILON);
				assertEquals(expected.getO_it_ca().getF(), actual.getO_it_ca().getF(), EPSILON);
				assertEquals(expected.getO_it_ca().getR(), actual.getO_it_ca().getR(), EPSILON);
				assertEquals(expected.getO_it_ca().getS(), actual.getO_it_ca().getS(), EPSILON);

				expected = actual;
				expected.getO_it_ca().addR(1);
				expected.getO_it_ee().addS(1);
			}
		}
	}

	@Test
	public void paperExample() throws Exception {
		TrustAssessment assessment;

		try (EmptyModel model = new EmptyModel();
		     TrustView trustView = model.openTrustView();
		     Configuration config = model.openConfiguration()) {

			// RCA1 -> RCA1 -> SCA1 -> EE1
			TrustComputation.validate(trustView, config, Arrays.asList(RCA1_RCA1, RCA1_SCA1, SCA1_EE1), 0.8, validation);

			assertEquals(2, trustView.getAssessments().size());

			assessment = trustView.getAssessment("RCA1-Key", "RCA1");
			assertEquals(1.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_RCA1, C);

			assessment = trustView.getAssessment("SCA1-Key", "SCA1");
			assertEquals(0.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_SCA1, C);

			assertEquals(1, trustView.getTrustedCertificates().size());
			for (TrustCertificate C : trustView.getTrustedCertificates())
				assertEqualsCert(SCA1_EE1, C);

			assertEquals(0, trustView.getUntrustedCertificates().size());


			// RCA1 -> RCA1 -> SCA2 -> EE2
			TrustComputation.validate(trustView, config, Arrays.asList(RCA1_RCA1, RCA1_SCA2, SCA2_EE2), 0.8, validation);

			assertEquals(3, trustView.getAssessments().size());

			assessment = trustView.getAssessment("RCA1-Key", "RCA1");
			assertEquals(2.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_RCA1, C);

			assessment = trustView.getAssessment("SCA1-Key", "SCA1");
			assertEquals(0.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_SCA1, C);

			assessment = trustView.getAssessment("SCA2-Key", "SCA2");
			assertEquals(0.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_SCA2, C);

			assertEquals(2, trustView.getTrustedCertificates().size());
			for (TrustCertificate C : trustView.getTrustedCertificates())
				if (C.getSerial().equals(SCA1_EE1.getSerial()))
					assertEqualsCert(SCA1_EE1, C);
				else
					assertEqualsCert(SCA2_EE2, C);

			assertEquals(0, trustView.getUntrustedCertificates().size());


			// RCA1 -> RCA1 -> SCA2 -> EE3
			TrustComputation.validate(trustView, config, Arrays.asList(RCA1_RCA1, RCA1_SCA2, SCA2_EE3), 0.8, validation);

			assertEquals(3, trustView.getAssessments().size());

			assessment = trustView.getAssessment("RCA1-Key", "RCA1");
			assertEquals(2.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_RCA1, C);

			assessment = trustView.getAssessment("SCA1-Key", "SCA1");
			assertEquals(0.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_SCA1, C);

			assessment = trustView.getAssessment("SCA2-Key", "SCA2");
			assertEquals(0.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_SCA2, C);

			assertEquals(2, trustView.getTrustedCertificates().size());
			for (TrustCertificate C : trustView.getTrustedCertificates())
				if (C.getSerial().equals(SCA1_EE1.getSerial()))
					assertEqualsCert(SCA1_EE1, C);
				else
					assertEqualsCert(SCA2_EE2, C);

			assertEquals(1, trustView.getUntrustedCertificates().size());
			for (TrustCertificate C : trustView.getUntrustedCertificates())
				assertEqualsCert(SCA2_EE3, C);


			// RCA2 -> RCA2 -> SCA3 -> EE4
			TrustComputation.validate(trustView, config, Arrays.asList(RCA2_RCA2, RCA2_SCA3, SCA3_EE4), 0.8, validation);

			assertEquals(5, trustView.getAssessments().size());

			assessment = trustView.getAssessment("RCA1-Key", "RCA1");
			assertEquals(2.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_RCA1, C);

			assessment = trustView.getAssessment("SCA1-Key", "SCA1");
			assertEquals(0.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_SCA1, C);

			assessment = trustView.getAssessment("SCA2-Key", "SCA2");
			assertEquals(0.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_SCA2, C);

			assessment = trustView.getAssessment("RCA2-Key", "RCA2");
			assertEquals(1.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA2_RCA2, C);

			assessment = trustView.getAssessment("SCA3-Key", "SCA3");
			assertEquals(0.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA2_SCA3, C);

			assertEquals(2, trustView.getTrustedCertificates().size());
			for (TrustCertificate C : trustView.getTrustedCertificates())
				if (C.getSerial().equals(SCA1_EE1.getSerial()))
					assertEqualsCert(SCA1_EE1, C);
				else
					assertEqualsCert(SCA2_EE2, C);

			assertEquals(2, trustView.getUntrustedCertificates().size());
			for (TrustCertificate C : trustView.getUntrustedCertificates())
				if (C.getSerial().equals(SCA2_EE3.getSerial()))
					assertEqualsCert(SCA2_EE3, C);
				else
					assertEqualsCert(SCA3_EE4, C);


			// RCA1 -> RCA1 -> SCA2 -> SCA3 -> EE5
			TrustComputation.validate(trustView, config, Arrays.asList(RCA1_RCA1, RCA1_SCA2, SCA2_SCA3, SCA3_EE5), 0.8, validation);

			assertEquals(5, trustView.getAssessments().size());

			assessment = trustView.getAssessment("RCA1-Key", "RCA1");
			assertEquals(2.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_RCA1, C);

			assessment = trustView.getAssessment("SCA1-Key", "SCA1");
			assertEquals(0.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_SCA1, C);

			assessment = trustView.getAssessment("SCA2-Key", "SCA2");
			assertEquals(1.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA1_SCA2, C);

			assessment = trustView.getAssessment("RCA2-Key", "RCA2");
			assertEquals(1.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(1, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				assertEqualsCert(RCA2_RCA2, C);

			assessment = trustView.getAssessment("SCA3-Key", "SCA3");
			assertEquals(0.0, assessment.getO_it_ca().getR(), EPSILON);
			assertEquals(0.0, assessment.getO_it_ca().getS(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getR(), EPSILON);
			assertEquals(1.0, assessment.getO_it_ee().getS(), EPSILON);

			assertEquals(2, assessment.getS().size());
			for (TrustCertificate C : assessment.getS())
				if (C.getSerial().equals(RCA2_SCA3.getSerial()))
					assertEqualsCert(RCA2_SCA3, C);
				else
					assertEqualsCert(SCA2_SCA3, C);

			assertEquals(3, trustView.getTrustedCertificates().size());
			for (TrustCertificate C : trustView.getTrustedCertificates())
				if (C.getSerial().equals(SCA1_EE1.getSerial()))
					assertEqualsCert(SCA1_EE1, C);
				else if (C.getSerial().equals(SCA2_EE2.getSerial()))
					assertEqualsCert(SCA2_EE2, C);
				else
					assertEqualsCert(SCA3_EE5, C);

			assertEquals(2, trustView.getUntrustedCertificates().size());
			for (TrustCertificate C : trustView.getUntrustedCertificates())
				if (C.getSerial().equals(SCA2_EE3.getSerial()))
					assertEqualsCert(SCA2_EE3, C);
				else
					assertEqualsCert(SCA3_EE4, C);
		}
	}
}
