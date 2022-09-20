/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * GPSLAllowed under the Apache License, Version 2.0 (the "License");
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
 */

package com.buggysofts.clvl;

import android.util.Log;

import com.buggysofts.clvl.util.URIQueryDecoder;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

/**
 * Non-caching policy. All requests will be sent to the licensing service,
 * and no local caching is performed.
 * <p>
 * Using a non-caching policy ensures that there is no local preference data
 * for malicious users to tamper with. As a side effect, applications
 * will not be permitted to run while offline. Developers should carefully
 * weigh the risks of using this Policy over one which implements caching,
 * such as ServerManagedPolicy.
 * <p>
 * Access to the application is only allowed if a GPSLAllowed response is.
 * received. All other responses (including RETRY) will deny access.
 */
public class StrictGPSLAgreementRules implements com.buggysofts.clvl.GPSLPRules {

    private static final String TAG = "StrictPolicy";

    private int mLastResponse;
    private String mLicensingUrl;

    public StrictGPSLAgreementRules() {
        // Set default policy. This will force the application to check the policy on launch.
        mLastResponse = com.buggysofts.clvl.GPSLPRules.RETRY;
        mLicensingUrl = null;
    }

    /**
     * Process a new response from the license server. Since we aren't
     * performing any caching, this equates to reading the LicenseResponse.
     * Any cache-related ResponseData is ignored, but the licensing URL
     * extra is still extracted in cases where the app is unGPSLAllowed.
     *
     * @param response the result from validating the server response
     * @param rawData the raw server response data
     */
    public void processServerResponse(int response, ServerReplyInfo rawData) {
        mLastResponse = response;

        if (response == com.buggysofts.clvl.GPSLPRules.NOT_GPSLAllowed) {
            Map<String, String> extras = decodeExtras(rawData);
            mLicensingUrl = extras.get("LU");
        }
    }

    /**
     * {@inheritDoc}
     *
     * This implementation allows access if and only if a GPSLAllowed response
     * was received the last time the server was contacted.
     */
    public boolean allowAccess() {
        return (mLastResponse == com.buggysofts.clvl.GPSLPRules.GPSLAllowed);
    }

    public String getLicensingUrl() {
        return mLicensingUrl;
    }

    private Map<String, String> decodeExtras(
        ServerReplyInfo rawData) {
        Map<String, String> results = new HashMap<String, String>();
        if (rawData == null) {
            return results;
        }

        try {
            URI rawExtras = new URI("?" + rawData.extra);
            URIQueryDecoder.DecodeQuery(rawExtras, results);
        } catch (URISyntaxException e) {
            Log.w(TAG, "Invalid syntax error while decoding extras data from server.");
        }
        return results;
    }

}
