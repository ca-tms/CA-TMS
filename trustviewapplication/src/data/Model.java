package data;

import data.sqlite.SQLiteBackedModel;

public final class Model {
	private static SQLiteBackedModel model = null;

	private static synchronized SQLiteBackedModel getModel() throws Exception {
		if (model == null)
			model = new SQLiteBackedModel();
		return model;
	}

	private Model() { }

	/**
	 * Opens a {@link TrustView} that can be used to retrieve and/or store
	 * information and must be closed afterwards in order for any modification
	 * made on the <code>TrustView</code> to take effect.
	 *
	 * Note: closing the <code>TrustView</code> may fail in case of concurrent
	 * modifications.
	 *
	 * @return the open <code>TrustView</code> instance
	 *
	 * @throws Exception if the <code>TrustView</code> could not be opened
	 */
	public static TrustView openTrustView() throws Exception {
		return getModel().openTrustView();
	}
}
