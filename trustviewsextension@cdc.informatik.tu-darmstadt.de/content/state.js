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
     * Loads the warning page
     * browser - the browser that should display the error page
     * url - the URL the user tried to visit
     * type - the error page type ("unreachable", "untrusted" or "unknown")
     * info - additional information (like "validated-first-seen", "validated-existing-expired-same-ca",
     *                                  "validated-existing-valid-same-ca", "validated-existing")
     */
    warnUser : function(browser, url, type, info) {
        if (type == "unreachable" || type == "untrusted" || type == "unknown") {
            if (info == "validated-first-seen")
                info = "firstseen";
            else if (info == "validated-existing-expired-same-ca")
                info = "samecaexpired";
            else if (info == "validated-existing-valid-same-ca")
                info = "samecavalid";
            else if (info == "validated-existing")
                info = "differentca";
            else
                info = "";

            browser.loadURIWithFlags(
                "chrome://trustviewsextension/content/error.xhtml?" +
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
