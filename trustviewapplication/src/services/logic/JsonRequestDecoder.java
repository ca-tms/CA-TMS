package services.logic;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

import javax.json.JsonArray;
import javax.json.JsonNumber;
import javax.json.JsonObject;

import util.CertificatePathValidity;
import data.Configuration;
import data.Model;
import data.ModelAccessException;
import data.TrustCertificate;

/**
 * Decoder for JSON requests
 */
public final class JsonRequestDecoder {
	private JsonRequestDecoder() { }

	/**
	 * Decodes a JSON request resulting in a {@link ValidationRequest} object
	 */
	public static ValidationRequest decode(JsonObject object)
			throws CertificateException, ModelAccessException {
		// get certificate chain
		JsonArray chain = object.getJsonArray("certChain");

		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		List<TrustCertificate> certifiactePath = new ArrayList<>(chain.size());

		for (JsonArray jsonCert : chain.getValuesAs(JsonArray.class)) {
			int i = 0;
			byte[] certBytes = new byte[jsonCert.size()];
			for (JsonNumber jsonByte : jsonCert.getValuesAs(JsonNumber.class))
				certBytes[i++] = (byte) jsonByte.intValue();

			certifiactePath.add(new TrustCertificate(
					factory.generateCertificate(
							new ByteArrayInputStream(certBytes))));
		}

		// get security level
		String securityLevel = Configuration.SECURITY_LEVEL_HIGH;
		switch (object.getString("secLevel", "")) {
		case "high":
			securityLevel = Configuration.SECURITY_LEVEL_HIGH;
			break;
		case "medium":
			securityLevel = Configuration.SECURITY_LEVEL_MEDIUM;
			break;
		case "low":
			securityLevel = Configuration.SECURITY_LEVEL_LOW;
			break;
		}

		// get validation result
		CertificatePathValidity certificatePathValidity =
				CertificatePathValidity.UNKNOWN;
		switch (object.getString("validationResult", "")) {
		case "valid":
			certificatePathValidity = CertificatePathValidity.VALID;
			break;
		case "invalid":
			certificatePathValidity = CertificatePathValidity.INVALID;
			break;
		case "unknown":
			certificatePathValidity = CertificatePathValidity.UNKNOWN;
			break;
		}

		// get host url
		String host = object.getString("url");

		// determine the validation request specification
		ValidationRequestSpec validationRequestSpec =
				ValidationRequestSpec.VALIDATE;
		switch (object.getString("validationSpec", "")) {
		case "validate":
			validationRequestSpec = ValidationRequestSpec.VALIDATE;
			break;
		case "validate-with-services":
			validationRequestSpec = ValidationRequestSpec.VALIDATE_WITH_SERVICES;
			break;
		case "validate-without-services":
			validationRequestSpec = ValidationRequestSpec.VALIDATE_WITHOUT_SERVICES;
			break;
		case "validate-trust-end-certificate":
			validationRequestSpec = ValidationRequestSpec.VALIDATE_TRUST_END_CERTIFICATE;
			break;
		case "retrieve-recommendation":
			validationRequestSpec = ValidationRequestSpec.RETRIEVE_RECOMMENDATION;
			break;
		}

		// return the decoded the request object
		try (Configuration config = Model.openConfiguration()) {
			return new ValidationRequest(host, certifiactePath, certificatePathValidity,
					config.get(securityLevel, Double.class), validationRequestSpec);
		}
	}
}
