/**
 * Communicates with the CTMS Application.
 */
TVE.CTMSCommunicator = {
    
    /**
     * Sends a validation request to the CTMS and returns the result ("TRUSTED", "UNTRUSTED" or "UNKNOWN").
     * certChain - the chain to validate
     * validationResult - Firefox's standard validation result
     * secLevel - user defined level ("heigh", "medium" or "low")
     */
    requestValidation : function(certChain, validationResult, secLevel) {
        // build object around data
        let data = new Object();
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
