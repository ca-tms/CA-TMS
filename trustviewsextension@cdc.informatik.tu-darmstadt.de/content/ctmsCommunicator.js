/**
 * Communicates with the CTMS Application.
 */
TVE.CTMSCommunicator = {
    
    requestValidation : function(certChain, validationResult, secLevel) {
        let data = new Object();
        data.certChain = certChain;
        data.validationResult = validationResult;
        data.secLevel = secLevel;

        let ctms = TVE.Prefs.getCharPref("ctmsURL") + ":" + TVE.Prefs.getCharPref("ctmsPort");
        
        let req = new XMLHttpRequest();
        req.open("POST", ctms, false);
        req.setRequestHeader("Content-Type", "application/json");
        req.send(JSON.stringify(data));
        return req.responseText;
    }
    
};
