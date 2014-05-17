package support;

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
public interface BoostrapService {
	/**
	 * Bootstraps the given trust view
	 * @param trustView
	 */
	void bootstrap(TrustView trustView);
}
