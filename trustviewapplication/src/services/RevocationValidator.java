package services;

import util.Util;
import buisness.RevocationValidation;
import data.Configuration;
import data.Model;
import data.ModelAccessException;
import data.TrustView;

/**
 * Validator for certificate revocation
 */
public class RevocationValidator {
	static final int MAX_ATTEMPTS = 60;
	static final int WAIT_ATTEMPT_MILLIS = 1000;

	private static Thread thread;

	private RevocationValidator() { }

	/**
	 * Updates the local revocation information for all certificates currently
	 * stored in the <code>TrustView</code>, potentially querying external
	 * revocation services and downloading revocation information
	 * @throws ModelAccessException if accessing the data model,
	 * which is to be updated, failed
	 */
	public static void validate() throws ModelAccessException {
		System.out.println("Performing revocation validation for trust view ...");
		RevocationValidation.Validator validator = null;

		int attempts = 0;
		while (true) {
			try {
				if (validator == null)
					try (TrustView trustView = Model.openTrustView();
					     Configuration config = Model.openConfiguration()) {
						final int crlTimeoutMillis =
								config.get(
									Configuration.REVOCATION_CRL_TIMEOUT_MILLIS,
									Integer.class);
						final int ocspTimeoutMillis =
								config.get(
									Configuration.REVOCATION_OCSP_TIMEOUT_MILLIS,
									Integer.class);

						validator = RevocationValidation.createValidator(
								trustView, crlTimeoutMillis, ocspTimeoutMillis);
					}

				while (!validator.isFinished()) {
					try (TrustView trustView = Model.openTrustView()) {
						validator.validate(trustView, 1);
						trustView.save();
					}

					try {
						Thread.sleep(1);
					}
					catch (InterruptedException e) { }
				}
			}
			catch (ModelAccessException e) {
				if (attempts == 0)
					e.printStackTrace();

				if (++attempts >= MAX_ATTEMPTS) {
					System.err.println(
							"Revocation information update failed. " +
							"The TrustView could not be updated.");
					throw e;
				}

				System.err.println(
						"Revocation information update failed. " +
						"This may happen due to concurrent access. " +
						"Retrying ...");

				try {
					Thread.sleep(WAIT_ATTEMPT_MILLIS);
				}
				catch (InterruptedException i) {
					i.printStackTrace();
				}
				continue;
			}

			System.out.println("Revocation validation completed.");
			break;
		}

		Util.tryClearCertificateFactoryCache();
	}

	/**
	 * Starts a background task that regularly updates the revocation
	 * information using {@link #validate()}
	 * @param checkInitially whether an initial update should be performed
	 * before regular checking
	 */
	public static synchronized void start(final boolean checkInitially) {
		if (thread == null) {
			thread = new Thread() {
				boolean checking = checkInitially;
				@Override
				public void run() {
					while(!Thread.currentThread().isInterrupted()) {
						long revocationCheckingIntervalMillis = 1000;
						if (checking)
							try (Configuration config = Model.openConfiguration()) {
								revocationCheckingIntervalMillis =
									config.get(
										Configuration.REVOCATION_CHECKING_INTERVAL_MILLIS,
										Long.class);
							}
							catch (Exception e) {
								// this should never happen, since we only read configuration values
								e.printStackTrace();
								return;
							}

						checking = true;

						try {
							Thread.sleep(revocationCheckingIntervalMillis);
							validate();
						}
						catch (InterruptedException e) {
							// this happens regularly on stop
						}
						catch (ModelAccessException e) {
							e.printStackTrace();
						}
					}
				}
			};
			thread.start();
		}
	}

	/**
	 * Stops the background task that regularly updates the revocation
	 * information
	 */
	public static synchronized void stop() {
		if (thread != null) {
			thread.interrupt();
			thread = null;
		}
	}
}
