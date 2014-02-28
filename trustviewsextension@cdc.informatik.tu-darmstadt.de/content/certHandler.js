/**
 * Handles the certificate stuff.
 */
TVE.CertHandler = {
    
    /**
     * Returns the certificate chain in raw DER format.
     * The return value is an array with one entry per certificate in the chain.
     * Each entry is a byte array which holds the raw data.
     * Entry 0 is the Root-CA's certificate, the last entry is the server's certificate.
     */
    getRawChain : function() {
        let secUI = window.getBrowser().selectedBrowser.securityUI; // get securityUI
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
     * Takes a security state and evaluates, if it is "valid", "invalid" or "unknown".
     */
    getValidationResult : function(secState) {
        if(secState & Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE)
            return "invalid";
        if(secState & Components.interfaces.nsIWebProgressListener.STATE_IS_BROKEN)
            return "unknown";
        if(secState & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE)
            return "valid";
    }
    
};
