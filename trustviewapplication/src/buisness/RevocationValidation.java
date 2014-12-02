package buisness;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import support.RevocationService;
import support.Service;
import support.revocation.RevocationInfo;
import util.Option;
import data.CRLInfo;
import data.OCSPInfo;
import data.TrustCertificate;
import data.TrustView;

/**
 * Implements revocation checking based on the information currently contained
 * in the {@link TrustView} and the information provided by external
 * {@link RevocationService}s
 */
public final class RevocationValidation {
	private RevocationValidation() { }

	/**
	 * Represents a validation service to check a set of certificates for
	 * revocation and update the <code>TrustView</code>
	 * @see RevocationValidation#createValidator(List, int, int)
	 * @see RevocationValidation#createValidator(TrustView, int, int)
	 */
	public static interface Validator {
		/**
		 * Checks the given certificates for revocation and updates the given
		 * {@link TrustView} accordingly. If needed, external revocation
		 * services are queried for revocation checking.
		 * This method must only be called once on each <code>Validator</code>
		 * instance for the same <code>TrustView</code> instance.
		 * @return <code>true</code> if none of the checked certificates is
		 * revoked, <code>false</code> otherwise
		 * @param trustView
		 */
		boolean validate(TrustView trustView);

		/**
		 * Checks the given certificates for revocation and updates the given
		 * {@link TrustView} accordingly. If needed, external revocation
		 * services are queried for revocation checking.
		 * Only the given maximum number of certificates are checked. The
		 * remaining certificates can be checked with subsequent method calls.
		 * This method must only be called once on each <code>Validator</code>
		 * instance for the same <code>TrustView</code> instance.
		 * @return <code>true</code> if none of the checked certificates is
		 * revoked, <code>false</code> otherwise
		 * @see #isFinished()
		 * @param trustView
		 * @param maxCertificates
		 */
		boolean validate(TrustView trustView, int maxCertificates);

		/**
		 * @return whether the validator has already validated all certificates;
		 * does not return <code>true</code> until the modifications to the
		 * <code>TrustView</code> have been saved
		 * @see #validate(TrustView, int)
		 */
		boolean isFinished();
	}

	/**
	 * Represents a certificate to be checked for revocation and associated
	 * revocation services
	 */
	private static final class ValidatorEntry {
		private final TrustCertificate certificate;
		private final Option<RevocationService<CRLInfo>> crlService;
		private final Option<RevocationService<OCSPInfo>> ocspService;

		/**
		 * Creates a new <code>ValidatorEntry</code> instance for the
		 * given certificate and the given associated revocation services
		 * @param certificate
		 * @param crlService
		 * @param ocspService
		 */
		private ValidatorEntry(TrustCertificate certificate,
				Option<RevocationService<CRLInfo>> crlService,
				Option<RevocationService<OCSPInfo>> ocspService) {
			this.certificate = certificate;
			this.crlService = crlService;
			this.ocspService = ocspService;
		}

		/** @return the certificate*/
		private TrustCertificate getCertificate() {
			return certificate;
		}

		/** @return the CRL revocation service for the certificate */
		private Option<RevocationService<CRLInfo>> getCRLService() {
			return crlService;
		}

		/** @return the OCSP revocation service for the certificate */
		private Option<RevocationService<OCSPInfo>> getOCSPService() {
			return ocspService;
		}
	}

	/** minimum amount of time to wait before checking a certificate again */
	private static final long CHECK_MIN_PERSISTENCE_MILLIS = 1800000;

	/** maximum amount of time to wait before checking a certificate again */
	private static final long CHECK_MAX_PERSISTENCE_MILLIS = 172800000;

	/** already checked certificates */
	private static ConcurrentMap<TrustCertificate, Long> checkedCertificates =
			new ConcurrentHashMap<>(4);

	/**
	 * @return a <code>Validator</code> instance for the given certificate path;
	 * the actual revocation checking can be performed using
	 * {@link Validator#validate(TrustView)};
	 * if needed, external revocation services are queried for revocation
	 * checking using the given timeouts;
	 * the revocation services will not be queried again for a certificate that
	 * was already checked recently depending on the next update time for the
	 * revocation service or a timeout if the revocation service could not be
	 * reached
	 * @param certificatePath
	 * @param crlTimeoutMillis
	 * @param ocspTimeoutMillis
	 */
	public static Validator createValidator(List<TrustCertificate> certificatePath,
			int crlTimeoutMillis, int ocspTimeoutMillis) {
		final List<ValidatorEntry> entries = createValidatorEntriesFromPath(
				certificatePath, crlTimeoutMillis, ocspTimeoutMillis);

		return new Validator() {
			final long nowMillis = new Date().getTime();
			final Map<TrustCertificate, Long> certificates = new HashMap<>();

			@Override
			public boolean validate(TrustView trustView) {
				return validate(trustView, entries.size());
			}

			@Override
			public boolean validate(TrustView trustView, int maxCertificates) {
				final int count = Math.min(entries.size(), maxCertificates);
				final int remaining = entries.size() - count;

				trustView.notify(new TrustView.Notification() {
					@Override
					public void saved() {
						for (Map.Entry<TrustCertificate, Long> entry : certificates.entrySet())
							if (entry.getValue() < 0)
								checkedCertificates.remove(entry.getKey());
							else
								checkedCertificates.put(entry.getKey(), entry.getValue());
						certificates.clear();

						int count = entries.size() - remaining;
						if (count > 0)
							entries.subList(0, count).clear();
					}
				});

				// clean up checked certificates
				for (Map.Entry<TrustCertificate, Long> entry : checkedCertificates.entrySet())
					if (entry.getValue() <= nowMillis)
						checkedCertificates.remove(entry.getKey());

				// check the certificates for revocation
				for (ValidatorEntry entry : entries.subList(0, count)) {
					final TrustCertificate certificate = entry.getCertificate();

					// directly invalidate revocation check
					// if we already know that the certificate has been revoked
					if (trustView.isCertificateRevoked(certificate)) {
						certificates.put(certificate, -1l);
						return false;
					}

					if (!checkedCertificates.containsKey(certificate)) {
						long nextCheckMillis = RevocationValidation.validate(trustView, entry);

						if (nextCheckMillis == -1) {
							certificates.put(certificate, -1l);
							return false;
						}

						nextCheckMillis = Math.max(nextCheckMillis,
								nowMillis + CHECK_MIN_PERSISTENCE_MILLIS);
						nextCheckMillis = Math.min(nextCheckMillis,
								nowMillis + CHECK_MAX_PERSISTENCE_MILLIS);
						certificates.put(certificate, nextCheckMillis);
					}
				}

				return true;
			}

			@Override
			public boolean isFinished() {
				return entries.isEmpty();
			}
		};
	}

	/**
	 *
	 * @return a <code>Validator</code> instance for all certificates contained
	 * in the given {@link TrustView};
	 * the actual revocation checking can be performed using
	 * {@link Validator#validate(TrustView)};
	 * if needed, external revocation services are queried for revocation
	 * checking using the given timeouts;
	 * the revocation services will not be queried again for a certificate that
	 * was already checked recently depending on the next update time for the
	 * revocation service
	 * @param trustView
	 * @param crlTimeoutMillis
	 * @param ocspTimeoutMillis
	 */
	public static Validator createValidator(TrustView trustView,
			int crlTimeoutMillis, int ocspTimeoutMillis) {
		final List<ValidatorEntry> entries = createValidatorEntriesFromTrustView(
				trustView, crlTimeoutMillis, ocspTimeoutMillis);

		return new Validator() {
			final List<TrustCertificate> certificates = new ArrayList<>();
			int entriesStart = 0;

			@Override
			public boolean validate(TrustView trustView) {
				return validate(trustView, entries.size());
			}

			@Override
			public boolean validate(TrustView trustView, int maxCertificates) {
				final int count = Math.min(entries.size() - entriesStart, maxCertificates);
				final int remaining = entries.size() - entriesStart - count;

				trustView.notify(new TrustView.Notification() {
					@Override
					public void saved() {
						for (TrustCertificate entry : certificates)
							checkedCertificates.remove(entry);
						certificates.clear();

						int count = entries.size() - entriesStart - remaining;
						if (count > 0)
							entriesStart += count;
						if (remaining == 0)
							entries.clear();
					}
				});

				// check the certificates for revocation
				for (ValidatorEntry entry : entries.subList(entriesStart, entriesStart + count)) {
					final TrustCertificate certificate = entry.getCertificate();

					if (trustView.isCertificateRevoked(certificate)) {
						certificates.add(certificate);
						continue;
					}

					long nextCheckMillis = RevocationValidation.validate(trustView, entry);
					if (nextCheckMillis == -1)
						certificates.add(certificate);
				}

				// update OCSP information if all certificates have been checked
				if (remaining == 0)
					for (ValidatorEntry entry : entries)
						if (entry.getOCSPService().isSet()) {
							RevocationService<OCSPInfo> ocspService =
									entry.getOCSPService().get();
							if (ocspService.getNextUpdate().isSet())
								trustView.addOCSP(ocspService.getInfo());
						}

				return certificates.isEmpty();
			}

			@Override
			public boolean isFinished() {
				return entries.isEmpty();
			}
		};
	}

	/**
	 * @return a collection of certificates and associated revocation services
	 * for the given certificate path using the given timeouts for revocation
	 * checking
	 * @param certificatePath
	 * @param crlTimeoutMillis
	 * @param ocspTimeoutMillis
	 */
	private static List<ValidatorEntry> createValidatorEntriesFromPath(
			List<TrustCertificate> certificatePath,
			int crlTimeoutMillis, int ocspTimeoutMillis) {
		Map<CRLInfo, CRLInfo> crlPool = new HashMap<>();
		Map<OCSPInfo, OCSPInfo> ocspPool = new HashMap<>();

		List<ValidatorEntry> entries = new ArrayList<>(certificatePath.size());

		for (int i = certificatePath.size() - 1; i >= 0; i--) {
			// use previous certificate in the chain for CRL and OCSP verification
			// we do not support indirect CRLs
			final TrustCertificate certificate = certificatePath.get(i);
			final TrustCertificate issuerCertificate =
					certificatePath.get(i == 0 ? 0 : i - 1);

			entries.add(
				createValidatorEntry(certificate, issuerCertificate,
					crlTimeoutMillis, ocspTimeoutMillis,
					crlPool, ocspPool));
		}

		return entries;
	}

	/**
	 * @return a collection of certificates and associated revocation services
	 * for all certificates contained in the given {@link TrustView} using the
	 * given timeouts for revocation checking; the actual revocation checking
	 * can be performed using {@link #validateAll(TrustView, Certificates)}
	 * (or {@link #validate(TrustView, Certificates)})
	 * @param trustView
	 * @param crlTimeoutMillis
	 * @param ocspTimeoutMillis
	 */
	private static List<ValidatorEntry> createValidatorEntriesFromTrustView(
			TrustView trustView, int crlTimeoutMillis, int ocspTimeoutMillis) {
		Map<CRLInfo, CRLInfo> crlPool = new HashMap<>();
		Map<OCSPInfo, OCSPInfo> ocspPool = new HashMap<>();

		// create mapping to look up issuer certificates and
		// create mapping to look up certificate revocation information
		Map<String, List<TrustCertificate>> issuerCertificates = new HashMap<>();
		Map<TrustCertificate, RevocationInfo> certificatesInfos = new HashMap<>();
		for (TrustCertificate certificate : trustView.getAllCertificates()) {
			List<TrustCertificate> certificates =
					issuerCertificates.get(certificate.getSubject());
			if (certificates == null)
				issuerCertificates.put(certificate.getSubject(),
						certificates = new ArrayList<>());
			certificates.add(certificate);

			certificatesInfos.put(certificate, new RevocationInfo(certificate));
		}

		// find issuer for each certificate
		List<ValidatorEntry> entries = new ArrayList<>();
		for (Map.Entry<TrustCertificate, RevocationInfo> certificateInfo :
				certificatesInfos.entrySet()) {
			final TrustCertificate certificate = certificateInfo.getKey();
			final RevocationInfo info = certificateInfo.getValue();
			final List<TrustCertificate> issuers =
					issuerCertificates.get(certificate.getIssuer());
			if (issuers == null)
				continue;

			// we do not need to find the issuer
			// if the certificate provides no revocation information
			if (info.getCRL().isEmpty() && info.getOCSP().isEmpty())
				continue;

			String issuerSerial = info.getAuthoritySerial();
			List<Byte> issuerId = info.getAuthorityKeyIdentifier();
			TrustCertificate issuerCertificate = null;

			// try to identify issuer certificate by serial number
			if (issuerSerial != null)
				for (TrustCertificate issuer : issuers)
					if (issuerSerial.equals(issuer.getSerial())) {
						issuerCertificate = issuer;
						break;
					}

			// try to identify issuer certificate by key identifier
			if (issuerId != null && issuerCertificate == null)
				for (TrustCertificate issuer : issuers)
					if (issuerId.equals(
							certificatesInfos.get(issuer).getSubjectKeyIdentifier())) {
						issuerCertificate = issuer;
						break;
					}

			// create certificate revocation service information
			// if the issuer could be identified
			if (issuerCertificate != null)
				entries.add(
					createValidatorEntry(certificate, issuerCertificate,
						crlTimeoutMillis, ocspTimeoutMillis,
						crlPool, ocspPool));

			// try all possible issuers if the issuer could not be identified
			if (issuerCertificate == null && issuerSerial == null && issuerId == null)
				for (TrustCertificate issuer : issuers)
					entries.add(
						createValidatorEntry(certificate, issuer,
							crlTimeoutMillis, ocspTimeoutMillis,
							crlPool, ocspPool));
		}

		return entries;
	}

	/**
	 * @return certificate revocation service information for the given
	 * certificate and its issuer using the given timeouts; the maps are used
	 * to employ the same {@link RevocationService} instances for certificate
	 * information that are created by different calls to this method but use
	 * the same revocation services
	 * @param certificate
	 * @param issuerCertificate
	 * @param revocationCRLTimeoutMillis
	 * @param revocationOCSPTimeoutMillis
	 * @param crlPool
	 * @param ocspPool
	 */
	private static ValidatorEntry createValidatorEntry(
			TrustCertificate certificate, TrustCertificate issuerCertificate,
			int revocationCRLTimeoutMillis, int revocationOCSPTimeoutMillis,
			Map<CRLInfo, CRLInfo> crlPool,
			Map<OCSPInfo, OCSPInfo> ocspPool) {
		final RevocationInfo info = new RevocationInfo(certificate);

		Option<RevocationService<CRLInfo>> crlService = new Option<>();
		if (!info.getCRL().isEmpty()) {
			CRLInfo crlInfo = new CRLInfo(issuerCertificate,
					stringListToURLList(info.getCRL()));

			CRLInfo existingCRLInfo = crlPool.get(crlInfo);
			if (existingCRLInfo == null)
				crlPool.put(crlInfo, crlInfo);
			else
				crlInfo = existingCRLInfo;

			crlService = new Option<>(
				Service.getRevocationService(
					Service.getRevocationService(crlInfo, revocationCRLTimeoutMillis)));
		}

		Option<RevocationService<OCSPInfo>> ocspService = new Option<>();
		if (!info.getOCSP().isEmpty()) {
			OCSPInfo ocspInfo = new OCSPInfo(issuerCertificate,
					stringListToURLList(info.getOCSP()));

			OCSPInfo existingOCSPInfo = ocspPool.get(ocspInfo);
			if (existingOCSPInfo == null)
				ocspPool.put(ocspInfo, ocspInfo);
			else
				ocspInfo = existingOCSPInfo;

			ocspService = new Option<>(
				Service.getRevocationService(
					Service.getRevocationService(ocspInfo, revocationOCSPTimeoutMillis)));
		}

		return new ValidatorEntry(certificate, crlService, ocspService);
	}

	/**
	 * @return <code>-1</code> if the given certificate is revoked or
	 * <code>0</code> if the given certificate is not to be considered revoked,
	 * but a next update date time for revocation checking could not be
	 * determined; otherwise the milliseconds time value that can be used to
	 * construct a {@link Date} object representing the next update time for
	 * revocation checking
	 * @param trustView
	 * @param entry
	 */
	private static long validate(TrustView trustView, ValidatorEntry entry) {
		final long nowMillis = new Date().getTime();
		final TrustCertificate certificate = entry.getCertificate();
		long nextCheckMillis = Long.MAX_VALUE;

		// directly invalidate revocation check for the certificate chain
		// if we already know that the certificate has been revoked
		if (trustView.isCertificateRevoked(certificate))
			return -1;

		// revocation checking using CRLs
		final Option<RevocationService<CRLInfo>> crlServiceOption =
				entry.getCRLService();
		if (crlServiceOption.isSet()) {
			final RevocationService<CRLInfo> crlService = crlServiceOption.get();
			final CRLInfo crlLocalInfo = trustView.getCRL(crlService.getInfo());

			// download latest CRL if
			// the CRL information is not already locally available or
			// the CRL data is not already locally available or
			// the CRL may have been updated in the meantime
			CRLInfo crlInfo = crlLocalInfo;
			if (crlLocalInfo == null ||
					!crlLocalInfo.getCRL().isSet() ||
					!crlLocalInfo.getNextUpdate().isSet() ||
					crlLocalInfo.getNextUpdate().get().getTime() <= nowMillis) {
				// retrieve CRL data
				if (!crlService.getInfo().getCRL().isSet() ||
						!crlService.getNextUpdate().isSet() ||
						crlService.getNextUpdate().get().getTime() <= nowMillis) {
					System.out.println("Updating local information for CRL ...");
					for (URL url : crlService.getInfo().getURLs())
						System.out.println("  URL: " + url);

					crlService.update();
				}

				// update local information if CRL was retrieved successfully
				// base next check waiting time on CRL next update date
				Option<Date> nextUpdate = crlService.getNextUpdate();
				if (nextUpdate.isSet() && nextUpdate.get().getTime() > nowMillis) {
					System.out.println("Local information for CRL updated.");

					crlInfo = crlService.getInfo();
					trustView.addCRL(crlService.getInfo());
				}
				else
					System.out.println("Failed to update local information for CRL.");
			}

			// check previously fetched and locally saved CRL if available
			if (crlInfo != null && crlInfo.getCRL().isSet()) {
				nextCheckMillis = Math.min(nextCheckMillis,
						crlInfo.getNextUpdate().get().getTime());

				if (crlInfo.isRevoked(certificate)) {
					trustView.setRevokedCertificate(certificate);
					return -1;
				}
			}
		}

		// revocation checking using OCSP
		final Option<RevocationService<OCSPInfo>> ocspServiceOption =
				entry.getOCSPService();
		if (ocspServiceOption.isSet()) {
			final RevocationService<OCSPInfo> ocspService = ocspServiceOption.get();
			final OCSPInfo ocspLocalInfo = trustView.getOCSP(ocspService.getInfo());

			// query OCSP service if
			// the certificate is not yet contained in the trust view
			// the OCSP information is not already locally available or
			// the OCSP service may have been updated in the meantime
			if (!trustView.hasCertificate(certificate) ||
					ocspLocalInfo == null ||
					!ocspLocalInfo.getNextUpdate().isSet() ||
					ocspLocalInfo.getNextUpdate().get().getTime() <= nowMillis) {
				System.out.println("Querying OCSP service ...");
				for (URL url : ocspService.getInfo().getURLs())
					System.out.println("  URL: " + url);

				// query OCSP service
				final boolean certificateRevoked =
						ocspService.isRevoked(certificate);

				// update local information if it is not yet available
				// base next check waiting time on OCSP next update date
				Option<Date> nextUpdate = ocspService.getNextUpdate();
				if (nextUpdate.isSet() && nextUpdate.get().getTime() > nowMillis) {
					System.out.println("OCSP service queried.");

					if (ocspLocalInfo == null)
						trustView.addOCSP(ocspService.getInfo());
					nextCheckMillis = Math.min(nextCheckMillis,
							nextUpdate.get().getTime());
				}
				else
					System.out.println("Failed to query OCSP service.");

				if (certificateRevoked) {
					trustView.setRevokedCertificate(certificate);
					return -1;
				}
			}
		}

		return nextCheckMillis == Long.MAX_VALUE ? 0 : nextCheckMillis;
	}

	/**
	 * @return a list of {@link URL}s converted from a list of {@link String}s
	 * @param strings
	 */
	private static List<URL> stringListToURLList(List<String> strings) {
		List<URL> urls = new ArrayList<>(strings.size());
		for (String string : strings)
			try {
				if (!string.startsWith("ldap://"))
					urls.add(new URL(string));
			}
			catch (MalformedURLException e) {
				e.printStackTrace();
			}

		if (!strings.isEmpty() && urls.isEmpty()) {
			System.out.println("Unsupported revocation service URL format");
			for (String string : strings)
				System.out.println("  URL: " + string);
		}

		return urls;
	}
}
