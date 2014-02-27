/**
 * Controls the user interface.
 */
TVE.UI = {
    
    resetPreferences : function() {
        TVE.Prefs.clearUserPref("ctmsURL");
        TVE.Prefs.clearUserPref("ctmsPort");
    }
    
};