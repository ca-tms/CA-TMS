/**
 * Handels the state.
 */
TVE.State = {
    
    allowedPages : {},
    
    unreachable: function(url) {
        
        function setCommand(event) {
            var doc = event.originalTarget.defaultView.document;
            if(doc.location == "chrome://trustviewsextension/content/ctmsUnreachable.xul") {
                var button = doc.getElementById("trustviewsextension-error-unreachable-tryagain");
                var cmd = "TVE.State.tryAgain('" + url + "');";
                button.setAttribute("oncommand", cmd);
                gBrowser.removeEventListener("DOMContentLoaded", setCommand, false);
            }
        }
        
        gBrowser.addEventListener("DOMContentLoaded", setCommand, false);
        gBrowser.loadURI("chrome://trustviewsextension/content/ctmsUnreachable.xul");
    },
    
    untrusted: function(url) {
        
        function setCommand(event) {
            var doc = event.originalTarget.defaultView.document;
            if(doc.location == "chrome://trustviewsextension/content/untrustedWebsite.xul") {
                var button = doc.getElementById("trustviewsextension-error-untrusted-tryagain");
                var cmd = "TVE.State.tryAgain('" + url + "');";
                button.setAttribute("oncommand", cmd);
                
                button = doc.getElementById("trustviewsextension-error-untrusted-forcevisiting");
                cmd = "TVE.State.forceVisit('" + url + "');";
                button.setAttribute("oncommand", cmd);
                
                gBrowser.removeEventListener("DOMContentLoaded", setCommand, false);
            }
        }
        
        gBrowser.addEventListener("DOMContentLoaded", setCommand, false);
        gBrowser.loadURI("chrome://trustviewsextension/content/untrustedWebsite.xul");
    },
    
    tryAgain : function(url) {
        gBrowser.loadURI(url);
    },
    
    forceVisit : function(url) {
        var host = this.getHostname(url);
        this.allowedPages[host] = true;
        this.tryAgain(url);
    },
    
    isAllowedPage : function(url) {
        var host = this.getHostname(url);
        if(host in this.allowedPages)
            return true;
        else
            return false;
    },
    
    getHostname: function(url) {
        let l = document.createElementNS("http://www.w3.org/1999/xhtml", "a");
        l.href = url;
        return l.hostname;
    }
    
};
