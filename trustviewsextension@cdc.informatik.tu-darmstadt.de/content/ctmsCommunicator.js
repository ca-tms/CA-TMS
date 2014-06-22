/**
 * Communicates with the CTMS Application.
 */
TVE.CTMSCommunicator = {
    
    /**
     * Sends a validation request to the CTMS and sets callback functions to deal with the result (which is "TRUSTED", "UNTRUSTED" or "UNKNOWN").
     * url - the url which delivers the certificate to check
     * certChain - the chain to validate
     * validationResult - Firefox's standard validation result ("invalid", "unknown" or "valid")
     * secLevel - user defined level ("high", "medium" or "low")
     * hostCertTrusted - boolean, if true accept cert even if unknown
     * successCallback - callback function for successfull requests
     * errorCallback - callback function for failed requests
     */
    requestValidation : function(url, certChain, validationResult, secLevel, hostCertTrusted, successCallback, errorCallback) {
        
        // build object around data
        let data = new Object();
        data.url = url;
        data.certChain = certChain;
        data.validationResult = validationResult;
        data.secLevel = secLevel;
        data.validationSpec = hostCertTrusted ? "validate-trust-end-certificate" : "validate";

        // read ctms address from preferences
        let ctms = TVE.Prefs.getCharPref("ctmsURL") + ":" + TVE.Prefs.getCharPref("ctmsPort");
        
        // send JSON encoded data over HTTP POST via asynchronous XMLHttpRequest
        let req = new XMLHttpRequest();
        req.onload = successCallback;
        req.onerror = errorCallback;
        req.open("POST", ctms); // using synchronous requests is deprecated and cause Firefox to freeze
        req.setRequestHeader("Content-Type", "application/json");
        req.send(JSON.stringify(data));

    }
    
};
