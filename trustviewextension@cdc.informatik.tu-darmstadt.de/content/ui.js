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
 *
 *
 * Controls the user interface.
 */
TVE.UI = {
    
    /**
     * Resets the preferences to default.
     */
    resetPreferences : function() {
        TVE.Prefs.clearUserPref("catmsURL");
        TVE.Prefs.clearUserPref("catmsPort");
    }
    
};