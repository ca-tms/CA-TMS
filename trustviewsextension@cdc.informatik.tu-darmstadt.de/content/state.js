/**
 * Handels the state.
 */
TVE.State = {
    
    /**
     * Holds hostnames for which CTMS validation is disabled during the session.
     */
    allowedPages : {},
    
    /**
     * Holds hostnames for which CTMS validation should trust the certificate even if result is unknown.
     */
    wantToTrust : {},
    
    /**
     * Loads the proper warning page when CTMS server is not reachable.
     */
    unreachable: function(browser, url) {
        
        // callback function for assigning a command to the button
        function setCommand(event) {
            var doc = event.originalTarget.defaultView.document;
            if(doc.location == "chrome://trustviewsextension/content/ctmsUnreachable.xul") {
                var button = doc.getElementById("trustviewsextension-error-unreachable-tryagain");
                var cmd = "TVE.State.tryAgain('" + url + "');";
                button.setAttribute("oncommand", cmd);
                browser.removeEventListener("DOMContentLoaded", setCommand, false);
            }
        }
        
        // register callback function and load warning page
        browser.addEventListener("DOMContentLoaded", setCommand, false);
        browser.loadURI("chrome://trustviewsextension/content/ctmsUnreachable.xul");
    },
    
    /**
     * Loads the proper warning page when validation result is untrusted.
     */
    untrusted: function(browser, url) {
        
        // callback function for assigning commands to the buttons
        function setCommand(event) {
            var doc = event.originalTarget.defaultView.document;
            if(doc.location == "chrome://trustviewsextension/content/untrustedWebsite.xul") {
                var button = doc.getElementById("trustviewsextension-error-untrusted-tryagain");
                var cmd = "TVE.State.tryAgain('" + url + "');";
                button.setAttribute("oncommand", cmd);
                
                button = doc.getElementById("trustviewsextension-error-untrusted-forcevisiting");
                cmd = "TVE.State.forceVisit('" + url + "');";
                button.setAttribute("oncommand", cmd);
                
                browser.removeEventListener("DOMContentLoaded", setCommand, false);
            }
        }
        
        // register callback function and load warning page
        browser.addEventListener("DOMContentLoaded", setCommand, false);
        browser.loadURI("chrome://trustviewsextension/content/untrustedWebsite.xul");
    },
    
    /**
     * Loads the proper warning page when validation result is unknown.
     */
    unknown: function(browser, url) {
        
        // callback function for assigning commands to the buttons
        function setCommand(event) {
            var doc = event.originalTarget.defaultView.document;
            if(doc.location == "chrome://trustviewsextension/content/unknownCert.xul") {
                var button = doc.getElementById("trustviewsextension-error-unknown-tryagain");
                var cmd = "TVE.State.tryAgain('" + url + "');";
                button.setAttribute("oncommand", cmd);
                
                button = doc.getElementById("trustviewsextension-error-unknown-settrusted");
                cmd = "TVE.State.trustAndVisit('" + url + "');";
                button.setAttribute("oncommand", cmd);
                
                browser.removeEventListener("DOMContentLoaded", setCommand, false);
            }
        }
        
        // register callback function and load warning page
        browser.addEventListener("DOMContentLoaded", setCommand, false);
        browser.loadURI("chrome://trustviewsextension/content/unknownCert.xul");
    },
    
    /**
     * Triggered from warning pages, tries to load url again.
     */
    tryAgain : function(url) {
        gBrowser.loadURI(url);
    },
    
    /**
     * Stores host in allowedPages and forces the visit to url.
     */
    forceVisit : function(url) {
        var host = this.getHostname(url);
        this.allowedPages[host] = true;
        this.tryAgain(url);
    },
    
    /**
     * Stores host in wantToTrust and and triggers a retry.
     */
    trustAndVisit : function(url) {
        var host = this.getHostname(url);
        this.wantToTrust[host] = true;
        this.tryAgain(url);
    },
    
    /**
     * Checks wheter url is excluded from CTMS validation or not.
     */
    isAllowedPage : function(url) {
        var host = this.getHostname(url);
        if(host in this.allowedPages)
            return true;
        else
            return false;
    },
    
    /**
     * Checks wheter url should be trusted if unknown or not.
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
