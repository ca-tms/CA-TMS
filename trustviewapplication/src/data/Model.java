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

	public static TrustView openTrustView() throws Exception {
		return getModel().openTrustView();
	}
}
