/**
 * Handles the certificate stuff.
 */
TVE.CertHandler = {
    
    getRawChain : function() {
        let secUI = window.getBrowser().selectedBrowser.securityUI; // get securityUI
        secUI.QueryInterface(Components.interfaces.nsISSLStatusProvider); // query ssl and certificate status
        let sslStatus = secUI.SSLStatus;
        let serverCert = sslStatus.serverCert;
        
        // store certificate chain in array
        let certChain = new Array(serverCert.getChain().length);         // as JavaScript objects
        let rawDERcertChain = new Array(serverCert.getChain().length);   // as byte arrays, representing cert in DER format
        // server's certificate is the last one, root CA's certificate is the first one
        for(let i = 0; i < serverCert.getChain().length; i++) {
            certChain[i] = serverCert.getChain().queryElementAt(serverCert.getChain().length-1-i, Components.interfaces.nsIX509Cert);
            rawDERcertChain[i] = certChain[i].getRawDER(new Object());
        }
        
        return rawDERcertChain;
    },
    
    getValidationResult : function(secState) {
        if(secState & Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE)
            return "invalid";
        if(secState & Components.interfaces.nsIWebProgressListener.STATE_IS_BROKEN)
            return "unknown";
        if(secState & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE)
            return "valid";
    }
    
};
