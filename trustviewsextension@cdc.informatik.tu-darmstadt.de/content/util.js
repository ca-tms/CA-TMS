(function()
{
	let ioService = Components.classes["@mozilla.org/network/io-service;1"].
		getService(Components.interfaces.nsIIOService)

	let docShell = getInterface(Components.interfaces.nsIDocShell)

	window.extractPageParameters = function() {
	    let parameters = {}
	    for each (let arg in location.search.substring(1).split(";")) {
	        let [, key, value] = /^([^=]+)=(.*)|.*$/.exec(arg)
	        if (key)
	            parameters[key] = decodeURIComponent(value)
	    }
	    return parameters
	}

	window.setAdressBarURL = function(url) {
	    docShell.setCurrentURI(ioService.newURI(url, null, null))
	}
})()
