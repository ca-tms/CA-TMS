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
 *      Pascal Weisenburger
 */
(function() {
    function request(data, callback) {
        // read catms address from preferences
        let catms = TVE.Prefs.getCharPref("catmsURL") + ":" + TVE.Prefs.getCharPref("catmsPort")

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
            req.open("POST", catms);
            req.setRequestHeader("Content-Type", "application/json")
            req.send(JSON.stringify(data))
        }
        catch (e) {
            callback(null)
        }
    }

    /**
     * Communicates with the CA-TMS Application.
     */
    TVE.CATMSCommunicator = {
        /**
         * Sends a validation request to the CA-TMS and sets callback functions to deal with the result
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
         * Sends a validation request to the CA-TMS and sets callback functions to deal with the result
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