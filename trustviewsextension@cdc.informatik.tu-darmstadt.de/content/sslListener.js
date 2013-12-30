/**
 * Listens to pageloads over SSL.
 * implements https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsIWebProgressListener
 */
TVE.SSLListener = {
    
    onLocationChange: function(aWebProgress, aRequest, aLocation, aFlags) {
        // nothing to do here
    },

    onProgressChange: function(aWebProgress, aRequest, aCurSelfProgress, aMaxSelfProgress, aCurTotalProgress, aMaxTotalProgress) {
        // nothing to do here
    },

    onSecurityChange: function(aWebProgress, aRequest, aState) {
        
        // if it's HTTPS and the request is still pending
        if((aState & Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE) && aRequest.isPending()) {
            
            // TODO: do something usefull here
            
        } else if(aState & Components.interfaces.nsIWebProgressListener.STATE_IS_BROKEN) {
            alert("State is Broken");
        }
        
    },

    onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {
        // nothing to do here
    },

    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {
        // nothing to do here
    }
    
};
