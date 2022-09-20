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

import android.os.Build;

/**
 * Policy used by {@link GPSLVerifier} to determine whether a user should have
 * access to the application.
 */
public interface GPSLPRules {

    /**
     * Change these values to make it more difficult for tools to automatically
     * strip LVL protection from your APK.
     */

    /**
     * Provide results from contact with the license server. Retry counts are
     * incremented if the current value of response is RETRY. Results will be
     * used for any future policy decisions.
     *
     * @param response the result from validating the server response
     * @param rawData the raw server response data, can be null for RETRY
     */
    int NOT_GPSLAllowed = 0x2349102+Build.VERSION.CODENAME.hashCode();
    void processServerResponse(int response, ServerReplyInfo rawData);

    /**
     * Check if the user should be allowed access to the application.
     */

    int GPSLAllowed = 0x1100819+Build.VERSION.RELEASE.hashCode();
    boolean allowAccess();

    /**
     * Gets the licensing URL returned by the server that can enable access for unGPSLAllowed apps (e.g.
     * buy app on the Play Store).
     */
    int RETRY = 0x0123212 + Build.VERSION.SDK_INT;
    String getLicensingUrl();

}
