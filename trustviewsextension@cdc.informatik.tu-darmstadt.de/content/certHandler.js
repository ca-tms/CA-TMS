/**
 * Handles the certificate stuff.
 */
TVE.CertHandler = {
    
    getCert : function() {
        
        let secUI = window.getBrowser().selectedBrowser.securityUI; // get securityUI
        secUI.QueryInterface(Components.interfaces.nsISSLStatusProvider); // query ssl and certificate status
        let sslStatus = secUI.SSLStatus;
        let serverCert = sslStatus.serverCert;
        let rawDER = serverCert.getRawDER(new Object()); // get byte array, representing cert in DER format
        
    }
    
};
