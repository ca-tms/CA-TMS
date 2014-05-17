package support.bootstrap;

import java.io.File;
import java.util.Collections;
import java.util.List;

import data.ModelAccessException;
import data.TrustView;
import support.BootstrapService;

public class FirefoxBootstrapService implements BootstrapService {
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
	public void bootstrap(double securityLevel) throws ModelAccessException {
		// TODO: implement
	}
}
