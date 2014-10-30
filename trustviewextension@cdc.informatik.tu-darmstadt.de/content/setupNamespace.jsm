var EXPORTED_SYMBOLS = ["TVE"];

/**
 * Define Trust Views Extension (TVE) namespace.
 */
if("undefined" == typeof(TVE)) {
    var TVE = {};
};

// assign preferences branch to namespace
TVE.Prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.trustviewsextension.");
TVE.Prefs.QueryInterface(Components.interfaces.nsIPrefBranch);
