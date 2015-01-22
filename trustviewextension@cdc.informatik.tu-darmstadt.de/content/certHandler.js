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
 *
 *
 * Handles the certificate stuff.
 */
TVE.CertHandler = {
    
    /**
     * Returns the certificate chain in raw DER format.
     * The return value is an array with one entry per certificate in the chain.
     * Each entry is a byte array which holds the raw data.
     * Entry 0 is the Root-CA's certificate, the last entry is the server's certificate.
     */
    getRawChain : function(browser) {
        let secUI = browser.securityUI; // get securityUI
        secUI.QueryInterface(Components.interfaces.nsISSLStatusProvider); // query ssl and certificate status
        let serverCert = secUI.SSLStatus.serverCert; // get certificate
        let chainLength = serverCert.getChain().length;
        
        // store certificate chain in byte array
        let rawDERcertChain = new Array(chainLength);
        // server's certificate is the last one, root CA's certificate is the first one
        for(let i = 0; i < chainLength; i++) {
            rawDERcertChain[i] = serverCert.getChain().queryElementAt(chainLength-1-i, Components.interfaces.nsIX509Cert).getRawDER(new Object());
        }
        
        return rawDERcertChain;
    },
    
    /**
     * Checks if SSLStatus is "valid" or "invalid".
     */
    getValidationResult : function(browser) {
        let secUI = browser.securityUI; // get securityUI
        secUI.QueryInterface(Components.interfaces.nsISSLStatusProvider); // query ssl status
        let status = secUI.SSLStatus; // get ssl status
        
        if(status.isUntrusted)
            return "invalid";
        else
            return "valid";
    }
    
};
