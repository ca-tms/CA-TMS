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
 *
 *
 * Handels the state.
 */
TVE.State = {
    
    /**
     * Holds hostnames for which CA-TMS validation is disabled during the session.
     */
    allowedPages : {},
    
    /**
     * Holds hostnames for which CA-TMS validation should trust the certificate even if result is unknown.
     */
    wantToTrust : {},
    
    /**
     * Loads the warning page
     * browser - the browser that should display the error page
     * url - the URL the user tried to visit
     * type - the error page type ("unreachable", "untrusted" or "unknown")
     * info - additional information ("firstseen", "samecaexpired", "samecavalid" or "differentca")
     * rawCertChain - the raw certificate chain object
     */
    warnUser : function(browser, url, type, info, rawCertChain) {
        if (type == "unreachable" || type == "untrusted" || type == "unknown") {
            if (info != "firstseen" && info != "samecavalid" &&
                info != "differentca" && info != "revoked")
                info = "";
            
            function contentLoaded(event) {
                let window = event.originalTarget.defaultView
                if (window.location.origin == "chrome://trustviewextension") {
                    window.rawCertChain = rawCertChain
                    browser.removeEventListener("DOMContentLoaded", contentLoaded, false);
                }
            }
            browser.addEventListener("DOMContentLoaded", contentLoaded, false);

            browser.loadURIWithFlags(
                "chrome://trustviewextension/content/error.xhtml?" +
                "id=" + type + ";" +
                "class=" + encodeURIComponent(info) + ";" +
                "url=" + encodeURIComponent(url),
                Components.interfaces.nsIWebNavigation.LOAD_FLAGS_BYPASS_HISTORY);
        }
    },
    
    /**
     * Stores host in allowedPages and forces the visit to url.
     */
    forceVisit : function(url) {
        var host = this.getHostname(url);
        this.allowedPages[host] = true;
        gBrowser.loadURI(url);
    },
    
    /**
     * Stores host in wantToTrust and and triggers a retry.
     */
    trustAndVisit : function(url) {
        var host = this.getHostname(url);
        this.wantToTrust[host] = true;
        gBrowser.loadURI(url);
    },
    
    /**
     * Checks whether url is excluded from CA-TMS validation or not.
     */
    isAllowedPage : function(url) {
        var host = this.getHostname(url);
        if(host in this.allowedPages)
            return true;
        else
            return false;
    },
    
    /**
     * Checks whether url should be trusted if unknown or not.
     */
    doWeWantToTrust : function(url) {
        var host = this.getHostname(url);
        if(host in this.wantToTrust)
            return true;
        else
            return false;
    },
    
    /**
     * Extracts the hostname from an url.
     */
    getHostname: function(url) {
        let l = document.createElementNS("http://www.w3.org/1999/xhtml", "a");
        l.href = url;
        return l.hostname;
    }
    
};
