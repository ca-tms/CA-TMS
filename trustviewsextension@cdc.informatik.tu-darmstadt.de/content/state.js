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
        browser.loadURIWithFlags(
            "chrome://trustviewsextension/content/ctmsUnreachable.xul?" +
            "url=" + encodeURIComponent(url),
            Components.interfaces.nsIWebNavigation.LOAD_FLAGS_BYPASS_HISTORY);
    },
    
    /**
     * Loads the proper warning page when validation result is untrusted.
     */
    untrusted: function(browser, url) {
        browser.loadURIWithFlags(
            "chrome://trustviewsextension/content/untrustedWebsite.xul?" +
            "url=" + encodeURIComponent(url),
            Components.interfaces.nsIWebNavigation.LOAD_FLAGS_BYPASS_HISTORY);
    },
    
    /**
     * Loads the proper warning page when validation result is unknown.
     */
    unknown: function(browser, url) {
        browser.loadURIWithFlags(
            "chrome://trustviewsextension/content/unknownCert.xul?" +
            "url=" + encodeURIComponent(url),
            Components.interfaces.nsIWebNavigation.LOAD_FLAGS_BYPASS_HISTORY);
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
     * Checks whether url is excluded from CTMS validation or not.
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
