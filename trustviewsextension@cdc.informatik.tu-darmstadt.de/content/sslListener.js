/**
 * Listens to pageloads over SSL.
 * implements https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIWebProgressListener
 */
TVE.SSLListener = {
    
    /**
     * Gets notified when the location changes.
     * When it's a HTTPS page, do additional validation.
     */
    onLocationChange: function(aBrowser, aWebProgress, aRequest, aLocation, aFlags) {
        
        // suspend request as long as it's possible (does not work later in the code)
        aRequest.suspend();
        
        let url = aLocation.asciiSpec;
        
        // if it's a HTTPS request and page is not excluded for this session:
        if(aRequest != null && aLocation.scheme == "https" && !TVE.State.isAllowedPage(url)) {
            
            var doValidation = {
                notify: function(timer) {
                    try {
                        
                        // parse standard validation result from Firefox/NSS
                        let validationResult = TVE.CertHandler.getValidationResult(aBrowser);
                        
                        if(validationResult == "valid") {
                        
                            // gather data for upcoming CTMS validation
                            let rawChain = TVE.CertHandler.getRawChain(aBrowser);
                            let secLevel = TVE.Prefs.getCharPref("secLevel");
                            
                            try {
                                // query CTMS!
                                let ctmsResult = TVE.CTMSCommunicator.requestValidation(url, rawChain, validationResult, secLevel);
                                if(ctmsResult == "UNTRUSTED") {
                                    aRequest.resume();
                                    // display warning page when result is bad
                                    TVE.State.untrusted(aBrowser, url);
                                } else {
                                    aRequest.resume();
                                }
                            } catch(err) {
                                // happens when CTMS server is unreachable
                                aRequest.resume();
                                TVE.State.unreachable(aBrowser, url);
                            }
                        
                        } else {
                            // when standard validation result is not valid
                            aRequest.resume();
                        }
                        
                    }
                    catch(err) {
                        // maybe it's too early to access the SSLStatus when the event handler kicks in
                        // in this case CertHandler.getValidationResult() throws an error which is caught here
                        // wait 10 ms and try it again
                        var timer = Components.classes["@mozilla.org/timer;1"].createInstance(Components.interfaces.nsITimer);
                        timer.initWithCallback(doValidation, 10, Components.interfaces.nsITimer.TYPE_ONE_SHOT);
                    }
                    
                }
            }
            
            doValidation.notify();
            
        } else {
            // continue normally when it's not a HTTPS request, we want to intercept
            aRequest.resume();
        }
        
    },

    onProgressChange: function(aBrowser, aWebProgress, aRequest, aCurSelfProgress, aMaxSelfProgress, aCurTotalProgress, aMaxTotalProgress) {
        // nothing to do here
    },

    onSecurityChange: function(aBrowser, aWebProgress, aRequest, aState) {
        // nothing to do here
    },

    onStateChange: function(aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {
        // nothing to do here        
    },

    onStatusChange: function(aBrowser, aWebProgress, aRequest, aStatus, aMessage) {
        // nothing to do here
    }
    
};
