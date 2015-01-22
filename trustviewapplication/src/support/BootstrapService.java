package support;

import data.ModelAccessException;
import data.TrustView;

/**
 * <p>Represents a bootstrap service.</p>
 *
 * <p>A method to bootstrap the {@link TrustView} is described in
 * <q>Trust views for the web pki</q> [1], section 4.3.1.</p>
 *
 * <p>[1] Johannes Braun, Florian Volk, Johannes Buchmann, and Max Mühlhäuser.
 * Trust views for the web pki. 2013.</p>
 */
public interface BootstrapService {
	/**
	 * Bootstraps the given trust view
	 * @param securityLevel the security level that is to be assumed while
	 * validating during the bootstrapping process
	 * @param observer an observer that can be used to gather information on the
	 * current bootstrapping progress, can be <code>null</code>
	 * @throws ModelAccee usedssException
	 */
	void bootstrap(double securityLevel, Observer observer) throws ModelAccessException;

	/**
	 * Represents the bootstrap service observer interface that can be used to
	 * gather information on the current bootstrapping progress
	 */
	static interface Observer {
		/**
		 * Informs an observer on the bootstrapping progress
		 * @param progress the progress between 0 and 1
		 * @param item the item currently processed
		 * @return returns <code>false</code> to indicate that the bootstrapping
		 * progress should be canceled
		 */
		boolean update(double progress, String item);
	}
}
