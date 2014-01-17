package util;

public final class Util {
	private Util() { }

	public static String getDataDirectory() {
		String OS = System.getProperty("os.name").toUpperCase();
		if (OS.contains("WIN"))
			return System.getenv("APPDATA");
		else if (OS.contains("MAC"))
			return System.getProperty("user.home") + "/Library/Application Support";
		else if (OS.contains("NUX")) {
			String dir = System.getenv("XDG_DATA_HOME");
			if (dir != null && !dir.isEmpty())
				return dir;
			return System.getProperty("user.home") + "/.local/share";
		}
		return System.getProperty("user.dir");
	}
}
