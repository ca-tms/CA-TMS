/**
 * Communicates with the CTMS Application.
 */
TVE.CTMSCommunicator = {
    
    /**
     * Sends a validation request to the CTMS and returns the result ("TRUSTED", "UNTRUSTED" or "UNKNOWN").
     * url - the url which delivers the certificate to check
     * certChain - the chain to validate
     * validationResult - Firefox's standard validation result ("invalid", "unknown" or "valid")
     * secLevel - user defined level ("high", "medium" or "low")
     */
    requestValidation : function(url, certChain, validationResult, secLevel) {
        // build object around data
        let data = new Object();
        data.url = url;
        data.certChain = certChain;
        data.validationResult = validationResult;
        data.secLevel = secLevel;

        // read ctms address from preferences
        let ctms = TVE.Prefs.getCharPref("ctmsURL") + ":" + TVE.Prefs.getCharPref("ctmsPort");
        
        // send JSON encoded data over HTTP POST
        let req = new XMLHttpRequest();
        req.open("POST", ctms, false);
        req.setRequestHeader("Content-Type", "application/json");
        req.send(JSON.stringify(data));
        return req.responseText;
    }
    
};
