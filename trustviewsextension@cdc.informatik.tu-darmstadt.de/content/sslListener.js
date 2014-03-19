/**
 * Listens to pageloads over SSL.
 * implements https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIWebProgressListener
 */
TVE.SSLListener = {
    
    onLocationChange: function(aBrowser, aWebProgress, aRequest, aLocation, aFlags) {
        // nothing to do here
    },

    onProgressChange: function(aBrowser, aWebProgress, aRequest, aCurSelfProgress, aMaxSelfProgress, aCurTotalProgress, aMaxTotalProgress) {
        // nothing to do here
    },

    /**
     * Gets notified when something SSL related happens and manages the additional validation.
     */
    onSecurityChange: function(aBrowser, aWebProgress, aRequest, aState) {
        
        // parse standard validation result from Firefox/NSS
        let validationResult = TVE.CertHandler.getValidationResult(aState);
        
        if(validationResult == "valid" && aRequest != null && !aRequest.isPending() && !TVE.State.isAllowedPage(aRequest.name)) {
            
            // gather data for upcoming CTMS validation
            let rawChain = TVE.CertHandler.getRawChain(aBrowser);
            let secLevel = TVE.Prefs.getCharPref("secLevel");
            
            try {
                // query CTMS!
                let ctmsResult = TVE.CTMSCommunicator.requestValidation(aRequest.name, rawChain, validationResult, secLevel);
                if(ctmsResult == "UNTRUSTED") {
                    // display warning page when result is bad
                    TVE.State.untrusted(aBrowser, aRequest.name);
                }
            } catch(err) {
                // should happen when CTMS server is unreachable
                TVE.State.unreachable(aBrowser, aRequest.name);
            }
            
        }
        
    },

    onStateChange: function(aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {
        // nothing to do here
    },

    onStatusChange: function(aBrowser, aWebProgress, aRequest, aStatus, aMessage) {
        // nothing to do here
    }
    
};
