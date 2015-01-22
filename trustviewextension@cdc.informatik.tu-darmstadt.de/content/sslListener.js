/*
 * This file is part of the CA Trust Management System (CA-TMS)
 *
 * Copyright 2015 by CA-TMS Team.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *      Jannik Vieten
 *      Pascal Weisenburger
 *
 *
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
                
                var validator = {
                    run: function() {
                        try {
                            
                            // parse standard validation result from Firefox/NSS
                            let validationResult = TVE.CertHandler.getValidationResult(aBrowser);
                            
                            if(validationResult == "valid") {
                            
                                // gather data for upcoming CA-TMS validation
                                let rawChain = TVE.CertHandler.getRawChain(aBrowser);
                                let secLevel = TVE.Prefs.getCharPref("secLevel");
                                let hostCertTrusted = TVE.State.doWeWantToTrust(url);
                                
                                // this is called when CA-TMS successfully answered the request
                                var callback = function(catmsResult) {
                                    let warningType = null;
                                    if (catmsResult == null)
                                        warningType = "unreachable";
                                    else if (catmsResult.result == "untrusted")
                                        warningType = "untrusted";
                                    else if (catmsResult.result == "unknown")
                                        warningType = "unknown";
                                    
                                    let warningInfo = ""
                                    if (catmsResult != null) {
                                        if (catmsResult.resultSpec == "validated-first-seen")
                                            warningInfo = "firstseen";
                                        else if (catmsResult.resultSpec == "validated-existing-valid-same-ca")
                                            warningInfo = "samecavalid";
                                        else if (catmsResult.resultSpec == "validated-existing")
                                            warningInfo = "differentca";
                                        else if (catmsResult.resultSpec == "validated-revoked")
                                            warningInfo = "revoked";
                                    }
                                    
                                    aRequest.resume();
                                    if (!!warningType)
                                        TVE.State.warnUser(aBrowser, url, warningType, warningInfo, rawChain);
                                }
                                
                                // query CA-TMS!
                                TVE.CATMSCommunicator.requestValidation(url, rawChain, validationResult, secLevel, hostCertTrusted, callback);
                            
                            } else {
                                // when standard validation result is not valid
                                aRequest.resume();
                            }
                            
                        }
                        catch (e) {
                            aRequest.resume();
                            throw e;
                        }
                        
                    }
                }
                
                // let this onLocationChange callback return first before performing the validation
                // which is to ensure that the security status information is available and up to date when validating
                var threadManager = Cc["@mozilla.org/thread-manager;1"].getService(Ci.nsIThreadManager);
                threadManager.currentThread.dispatch(validator, Ci.nsIEventTarget.DISPATCH_NORMAL);
                
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
