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

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.text.TextUtils;
import android.util.Log;

import com.buggysofts.clvl.util.Base64;
import com.buggysofts.clvl.util.Base64DecoderException;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.zip.CRC32;

/**
 * Contains data related to a licensing request and methods to verify
 * and process the response.
 */
class GPSLLVerifier {

    private static final String TAG = "LicenseValidator";

    // Server response codes.

    private static final int ERROR_NOT_MARKET_MANAGED = 0x3;
    private static final int ERROR_SERVER_FAILURE = 0x4;
    private static final int ERROR_OVER_QUOTA = 0x5;

    private static final int ERROR_CONTACTING_SERVER = 0x101;
    private static final int ERROR_INVALID_PACKAGE_NAME = 0x102;
    private static final int ERROR_NON_MATCHING_UID = 0x103;

    private static final int GPSLAllowed_OLD_KEY = 0x2;
    private static final int GPSLAllowed = 0x0;
    private static final int NOT_GPSLAllowed = 0x1;


    private final Context mContext;
    private final com.buggysofts.clvl.GPSLPRules mGPSLPRules;
    private final GPSLCListener mCallback;
    private final int mNonce;
    private final String mPackageName;
    private final String mVersionCode;
    private final GPSLDShrinker mGPSLDShrinker;

    GPSLLVerifier(Context context,
                  com.buggysofts.clvl.GPSLPRules GPSLPRules,
                  GPSLDShrinker GPSLDShrinker,
                  GPSLCListener callback,
                  int nonce,
                  String packageName,
                  String versionCode) {
        mContext = context;
        mGPSLPRules = GPSLPRules;
        mGPSLDShrinker = GPSLDShrinker;
        mCallback = callback;
        mNonce = nonce;
        mPackageName = packageName;
        mVersionCode = versionCode;
    }

    public GPSLCListener getCallback() {
        return mCallback;
    }

    public int getNonce() {
        return mNonce;
    }

    public String getPackageName() {
        return mPackageName;
    }

    private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

    /**
     * Verifies the response from server and calls appropriate callback method.
     *
     * @param publicKey public key associated with the developer account
     * @param responseCode server response code
     * @param signedData signed data from server
     * @param signature server signature
     */
    public void verify(PublicKey publicKey, int responseCode, String signedData, String signature) {
        String userId = null;

        // Skip signature check for unsuccessful requests
        ServerReplyInfo data = null;
        if (responseCode == GPSLAllowed ||
            responseCode == NOT_GPSLAllowed ||
            responseCode == GPSLAllowed_OLD_KEY) {
            // Verify signature.
            try {
                if (TextUtils.isEmpty(signedData)) {
                    Log.e(
                        TAG,
                        String.format(
                            "%s - %s",
                            "Signature verification failed: signedData is empty",
                            "(Device not signed-in to any Google accounts?)"
                        )
                    );
                    handleInvalidResponse();
                    return;
                }

                Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
                sig.initVerify(publicKey);
                sig.update(signedData.getBytes());

                if (!sig.verify(Base64.decode(signature))) {
                    Log.e(TAG, "Signature verification failed.");
                    handleInvalidResponse();
                    return;
                }
            } catch (NoSuchAlgorithmException | SignatureException e) {
                // NoSuchAlgorithmException will always be on an Android compatible device.
                // SignatureException may occur.
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                handleApplicationError(GPSLCListener.ERROR_INVALID_PUBLIC_KEY);
                return;
            } catch (Base64DecoderException e) {
                Log.e(TAG, "Could not Base64-decode signature.");
                handleInvalidResponse();
                return;
            }

            // Parse and validate response.
            try {
                data = ServerReplyInfo.parse(signedData);
            } catch (IllegalArgumentException e) {
                Log.e(TAG, "Could not parse response.");
                handleInvalidResponse();
                return;
            }

            if (data.responseCode != responseCode) {
                Log.e(TAG, "Response codes don't match.");
                handleInvalidResponse();
                return;
            }

            if (data.nonce != mNonce) {
                Log.e(TAG, "Nonce doesn't match.");
                handleInvalidResponse();
                return;
            }

            if (!data.packageName.equals(mPackageName)) {
                Log.e(TAG, "Package name doesn't match.");
                handleInvalidResponse();
                return;
            }

            if (!data.versionCode.equals(mVersionCode)) {
                Log.e(TAG, "Version codes don't match.");
                handleInvalidResponse();
                return;
            }

            // Application-specific user identifier.
            userId = data.userId;
            if (TextUtils.isEmpty(userId)) {
                Log.e(TAG, "User identifier is empty.");
                handleInvalidResponse();
                return;
            }
        }

        long basePackageHashLong = getBasePackageHash();
        int basePackageHashShort = ((int) basePackageHashLong);
        final int transformed_key_GPSLAllowed = GPSLAllowed - basePackageHashShort;
        final int transformed_key_GPSLAllowed_OLD_KEY = GPSLAllowed_OLD_KEY + basePackageHashShort;
        final int transformed_key_NOT_GPSLAllowed = NOT_GPSLAllowed - basePackageHashShort;
        final int transformed_key_ERROR_CONTACTING_SERVER = ERROR_CONTACTING_SERVER + basePackageHashShort;
        final int transformed_key_ERROR_SERVER_FAILURE = ERROR_SERVER_FAILURE - basePackageHashShort;
        final int transformed_key_ERROR_OVER_QUOTA = ERROR_OVER_QUOTA + basePackageHashShort;
        final int transformed_key_ERROR_INVALID_PACKAGE_NAME = ERROR_INVALID_PACKAGE_NAME - basePackageHashShort;
        final int transformed_key_ERROR_NON_MATCHING_UID = ERROR_NON_MATCHING_UID + basePackageHashShort;
        final int transformed_key_ERROR_NOT_MARKET_MANAGED = ERROR_NOT_MARKET_MANAGED - basePackageHashShort;

        int transformedResponseCode = 0;
        if (responseCode == GPSLAllowed) {
            transformedResponseCode = GPSLAllowed - basePackageHashShort;
        } else if (responseCode == GPSLAllowed_OLD_KEY) {
            transformedResponseCode = GPSLAllowed_OLD_KEY + basePackageHashShort;
        } else if (responseCode == NOT_GPSLAllowed) {
            transformedResponseCode = NOT_GPSLAllowed - basePackageHashShort;
        } else if (responseCode == ERROR_CONTACTING_SERVER) {
            transformedResponseCode = ERROR_CONTACTING_SERVER + basePackageHashShort;
        } else if (responseCode == ERROR_SERVER_FAILURE) {
            transformedResponseCode = ERROR_SERVER_FAILURE - basePackageHashShort;
        } else if (responseCode == ERROR_OVER_QUOTA) {
            transformedResponseCode = ERROR_OVER_QUOTA + basePackageHashShort;
        } else if (responseCode == ERROR_INVALID_PACKAGE_NAME) {
            transformedResponseCode = ERROR_INVALID_PACKAGE_NAME - basePackageHashShort;
        } else if (responseCode == ERROR_NON_MATCHING_UID) {
            transformedResponseCode = ERROR_NON_MATCHING_UID + basePackageHashShort;
        } else if (responseCode == ERROR_NOT_MARKET_MANAGED) {
            transformedResponseCode = ERROR_NOT_MARKET_MANAGED - basePackageHashShort;
        } else {
            transformedResponseCode = -1234567890;
        }

        if(transformedResponseCode == transformed_key_GPSLAllowed ||
            transformedResponseCode == transformed_key_GPSLAllowed_OLD_KEY){
            int limiterResponse = mGPSLDShrinker.isDeviceAllowed(userId);
            handleResponse(data, basePackageHashLong, limiterResponse);
        } else if (transformedResponseCode == transformed_key_NOT_GPSLAllowed) {
            handleResponse(data, basePackageHashLong, com.buggysofts.clvl.GPSLPRules.NOT_GPSLAllowed);
        } else if (transformedResponseCode == transformed_key_ERROR_CONTACTING_SERVER) {
            Log.w(TAG, "Error contacting licensing server.");
            handleResponse(data, basePackageHashLong, com.buggysofts.clvl.GPSLPRules.RETRY);
        } else if (transformedResponseCode == transformed_key_ERROR_SERVER_FAILURE) {
            Log.w(TAG, "An error has occurred on the licensing server.");
            handleResponse(data, basePackageHashLong, com.buggysofts.clvl.GPSLPRules.RETRY);
        } else if (transformedResponseCode == transformed_key_ERROR_OVER_QUOTA) {
            Log.w(TAG, "Licensing server is refusing to talk to this device, over quota.");
            handleResponse(data, basePackageHashLong, com.buggysofts.clvl.GPSLPRules.RETRY);
        } else if (transformedResponseCode == transformed_key_ERROR_INVALID_PACKAGE_NAME) {
            handleApplicationError(GPSLCListener.ERROR_INVALID_PACKAGE_NAME);
        } else if (transformedResponseCode == transformed_key_ERROR_NON_MATCHING_UID) {
            handleApplicationError(GPSLCListener.ERROR_NON_MATCHING_UID);
        } else if (transformedResponseCode == transformed_key_ERROR_NOT_MARKET_MANAGED) {
            handleApplicationError(GPSLCListener.ERROR_NOT_MARKET_MANAGED);
        } else {
            Log.e(TAG, "Unknown response code for license check.");
            handleInvalidResponse();
        }
    }

    /**
     * Confers with policy and calls appropriate callback method.
     */
    private void handleResponse(ServerReplyInfo rawData, long currentPackageHash, int response) {
        // Update policy data and increment retry counter (if needed)
        mGPSLPRules.processServerResponse(response, rawData);

        // Given everything we know, including cached data, ask the policy if we should grant
        // access.
        if (mGPSLPRules.allowAccess()) {
            mCallback.GPSLValidated(response);
        } else {
            mCallback.GPSLDValidated(response);
        }
    }

    private void handleApplicationError(int code) {
        mCallback.applicationError(code);
    }

    private void handleInvalidResponse() {
        mCallback.GPSLDValidated(com.buggysofts.clvl.GPSLPRules.NOT_GPSLAllowed);
    }

    private long getBasePackageHash(){
        long ret = -1;

        PackageInfo info = null;
        try {
            info = mContext.getPackageManager().getPackageInfo(getPackageName(),0);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        } finally {
            if(info != null){
                ret = getFileCrc32(info.applicationInfo.publicSourceDir);
            }
        }

        return ret;
    }

    /**
     * */
    private long getRemoteHash() {
        // todo change //
        return 100L;
    }

    /**
     * Compute crc32 hash of the given file.
     * */
    private long getFileCrc32(String filePath) {
        long ret = -1;

        CRC32 crc32 = new CRC32();
        BufferedInputStream bin = null;
        try {
            bin = new BufferedInputStream(
                new FileInputStream(
                    filePath
                )
            );
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } finally {
            if(bin != null){
                try{
                    int readNum = 0;
                    byte[] data = new byte[4096];
                    while ((readNum = bin.read(data)) >= 0){
                        crc32.update(Arrays.copyOfRange(data,0, readNum - 1));
                    }
                } catch (Exception e){
                    e.printStackTrace();
                } finally {
                    ret = crc32.getValue();

                    try{
                        bin.close();
                    } catch (Exception e){
                        e.printStackTrace();
                    }
                }
            }
        }

        return ret;
    }

}
