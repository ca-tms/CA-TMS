/**
 * Communicates with the CTMS Application.
 */
TVE.CTMSCommunicator = {
    
    requestValidation : function(certChain, validationResult, secLevel, reqCertainty) {
        let data = new Object();
        data.certChain = certChain;
        data.validationResult = validationResult;
        data.secLevel = secLevel;
        data.reqCertainty = reqCertainty;

        let req = new XMLHttpRequest();
        req.open('POST', 'http://localhost:8084', false);
        req.setRequestHeader("Content-Type", "application/json");
        req.send(JSON.stringify(data));
        return req.responseText;
    }
    
};
