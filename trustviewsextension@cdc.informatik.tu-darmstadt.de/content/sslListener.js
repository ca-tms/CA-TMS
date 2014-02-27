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

    onSecurityChange: function(aWebProgress, aRequest, aState) {
        
        let validationResult = TVE.CertHandler.getValidationResult(aState);
        
        if(validationResult == "valid" && aRequest != null && aRequest.isPending() && !TVE.State.isAllowedPage(aRequest.name)) {
            
            let rawChain = TVE.CertHandler.getRawChain();
            let secLevel = TVE.Prefs.getCharPref("secLevel");
            
            try {
                let ctmsResult = TVE.CTMSCommunicator.requestValidation(rawChain, validationResult, secLevel);
                if(ctmsResult == "UNTRUSTED") {
                    TVE.State.untrusted(aRequest.name);
                }
            } catch(err) {
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
