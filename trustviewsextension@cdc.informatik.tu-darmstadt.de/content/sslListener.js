/**
 * Listens to pageloads over SSL.
 * implements https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIWebProgressListener
 */
TVE.SSLListener = {
    
    onLocationChange: function(aWebProgress, aRequest, aLocation, aFlags) {
        // nothing to do here
    },

    onProgressChange: function(aWebProgress, aRequest, aCurSelfProgress, aMaxSelfProgress, aCurTotalProgress, aMaxTotalProgress) {
        // nothing to do here
    },

    /**
     * Gets notified when something SSL related happens and manages the additional validation.
     */
    onSecurityChange: function(aWebProgress, aRequest, aState) {
        
        // get standard validation result from Firefox/NSS
        let validationResult = TVE.CertHandler.getValidationResult(aState);
        
        if(validationResult == "valid" && aRequest != null && aRequest.isPending() && !TVE.State.isAllowedPage(aRequest.name)) {
            
            // gather data for upcoming CTMS validation
            let rawChain = TVE.CertHandler.getRawChain();
            let secLevel = TVE.Prefs.getCharPref("secLevel");
            
            try {
                // query CTMS!
                let ctmsResult = TVE.CTMSCommunicator.requestValidation(rawChain, validationResult, secLevel);
                if(ctmsResult == "UNTRUSTED") {
                    // display warning page when result is bad
                    TVE.State.untrusted(aRequest.name);
                }
            } catch(err) {
                // should happen when CTMS server is unreachable
                TVE.State.unreachable(aRequest.name);
            }
            
        }
        
    },

    onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {
        // nothing to do here
    },

    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {
        // nothing to do here
    }
    
};
