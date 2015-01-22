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
 */

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
        toolbar.insertItem("trustviewextension-toolbarbutton", null);
        toolbar.setAttribute("currentset", toolbar.currentSet);
        document.persist(toolbar.id, "currentset");
        
        let item = document.getElementById("trustviewextension-secLevelMenuitem-medium");
        item.setAttribute("checked", true);
    }
};
