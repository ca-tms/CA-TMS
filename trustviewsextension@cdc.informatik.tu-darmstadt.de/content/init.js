// register SSL Listener
getBrowser().addTabsProgressListener(TVE.SSLListener);


// on first run:
// * add toolbarbutton automatically
// * select default security level menuitem
window.addEventListener("load", function() { TVE.firstRun(); }, false);
TVE.firstRun = function() {
    if(!TVE.Prefs.getBoolPref("firstRunDone")) {
        TVE.Prefs.setBoolPref("firstRunDone", true);
        
        let toolbar = document.getElementById("nav-bar");
        toolbar.insertItem("trustviewsextension-toolbarbutton", null);
        toolbar.setAttribute("currentset", toolbar.currentSet);
        document.persist(toolbar.id, "currentset");
        
        let item = document.getElementById("trustviewsextension-secLevelMenuitem-medium");
        item.setAttribute("checked", true);
    }
};
