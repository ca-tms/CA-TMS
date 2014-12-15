(function() {
    function request(data, callback) {
        // read ctms address from preferences
        let ctms = TVE.Prefs.getCharPref("ctmsURL") + ":" + TVE.Prefs.getCharPref("ctmsPort")

        // send JSON encoded data over HTTP POST via asynchronous XMLHttpRequest
        // using synchronous requests is deprecated and cause Firefox to freeze
        let req = new XMLHttpRequest()
        req.onload = function(event) {
            callback(JSON.parse(event.target.responseText))
        }
        req.onerror = function(event) {
            callback(null)
        }
        try {
            req.open("POST", ctms);
            req.setRequestHeader("Content-Type", "application/json")
            req.send(JSON.stringify(data))
        }
        catch (e) {
            callback(null)
        }
    }

    /**
     * Communicates with the CTMS Application.
     */
    TVE.CTMSCommunicator = {
        /**
         * Sends a validation request to the CTMS and sets callback functions to deal with the result
         * url - the url which delivers the certificate to check
         * certChain - the chain to validate
         * validationResult - Firefox's standard validation result ("invalid", "unknown" or "valid")
         * secLevel - user defined level ("high", "medium" or "low")
         * trustHostCert - boolean, if true accept cert even if unknown
         * callback - callback function that gets the response as object or null if the request failed
         */
        requestValidation: function(url, certChain, validationResult, secLevel, trustHostCert, callback) {
            request({
                url: url,
                certChain: certChain,
                validationResult: validationResult,
                secLevel: secLevel,
                validationSpec: trustHostCert ? "validate-trust-end-certificate" : "validate"
            }, callback)
        },

        /**
         * Sends a validation request to the CTMS and sets callback functions to deal with the result
         * url - the url which delivers the certificate to check
         * certChain - the chain to validate
         * callback - callback function that gets the response as object or null if the request failed
         */
        requestRecommendation: function(url, certChain, callback) {
            request({
                url: url,
                certChain: certChain,
                validationSpec: "retrieve-recommendation"
            }, callback)
        }
    }
})()