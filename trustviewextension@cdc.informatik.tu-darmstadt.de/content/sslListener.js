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
        
        if(aRequest != null) {
        
            // suspend request as long as it's possible (does not work later in the code)
            aRequest.suspend();
            
            let url = aLocation.asciiSpec;
            
            // if it's a HTTPS request and page is not excluded for this session:
            if(aLocation.scheme == "https" && !TVE.State.isAllowedPage(url)) {
                
                var doValidation = {
                    notify: function(timer) {
                        try {
                            
                            // parse standard validation result from Firefox/NSS
                            let validationResult = TVE.CertHandler.getValidationResult(aBrowser);
                            
                            if(validationResult == "valid") {
                            
                                // gather data for upcoming CTMS validation
                                let rawChain = TVE.CertHandler.getRawChain(aBrowser);
                                let secLevel = TVE.Prefs.getCharPref("secLevel");
                                let hostCertTrusted = TVE.State.doWeWantToTrust(url);
                                
                                // this is called when CTMS successfully answered the request
                                var callback = function(ctmsResult) {
                                    let warningType = null;
                                    if (ctmsResult == null)
                                        warningType = "unreachable";
                                    else if (ctmsResult.result == "untrusted")
                                        warningType = "untrusted";
                                    else if (ctmsResult.result == "unknown")
                                        warningType = "unknown";
                                    
                                    let warningInfo = ""
                                    if (ctmsResult != null) {
                                        if (ctmsResult.resultSpec == "validated-first-seen")
                                            warningInfo = "firstseen";
                                        else if (ctmsResult.resultSpec == "validated-existing-valid-same-ca")
                                            warningInfo = "samecavalid";
                                        else if (ctmsResult.resultSpec == "validated-existing")
                                            warningInfo = "differentca";
                                        else if (ctmsResult.resultSpec == "validated-revoked")
                                            warningInfo = "revoked";
                                    }
                                    
                                    aRequest.resume();
                                    if (!!warningType)
                                        TVE.State.warnUser(aBrowser, url, warningType, warningInfo, rawChain);
                                }
                                
                                // query CTMS!
                                TVE.CTMSCommunicator.requestValidation(url, rawChain, validationResult, secLevel, hostCertTrusted, callback);
                            
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
        
        }
        
    },

    onProgressChange: function(aBrowser, aWebProgress, aRequest, aCurSelfProgress, aMaxSelfProgress, aCurTotalProgress, aMaxTotalProgress) {
        // nothing to do here
    },

    onSecurityChange: function(aBrowser, aWebProgress, aRequest, aState) {
        // nothing to do here
        // the idea was to do the handling here, but unfortunately there is no onSecurityChange event fired
        // when a link is opened in a new tab, so this becomes useless
    },

    onStateChange: function(aBrowser, aWebProgress, aRequest, aStateFlags, aStatus) {
        // nothing to do here        
    },

    onStatusChange: function(aBrowser, aWebProgress, aRequest, aStatus, aMessage) {
        // nothing to do here
    }
    
};
