package support.bootstrap;

import java.io.File;
import java.util.Collections;
import java.util.List;

import data.TrustView;
import support.BoostrapService;

public class FirefoxBootstrapService implements BoostrapService {
	public FirefoxBootstrapService(File bootstrapBase) {
		// TODO: implement
	}

	public static boolean canUseAsBootstrapBase(File bootstrapBase) {
		// TODO: implement
		return false;
	}

	public static List<File> findBootstrapBases() {
		// TODO: implement
		return Collections.emptyList();
	}

	@Override
	public void bootstrap(TrustView trustView) {
		// TODO: implement
	}
}
