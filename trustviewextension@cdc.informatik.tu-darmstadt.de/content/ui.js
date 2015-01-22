/**
 * Controls the user interface.
 */
TVE.UI = {
    
    /**
     * Resets the preferences to default.
     */
    resetPreferences : function() {
        TVE.Prefs.clearUserPref("catmsURL");
        TVE.Prefs.clearUserPref("catmsPort");
    }
    
};