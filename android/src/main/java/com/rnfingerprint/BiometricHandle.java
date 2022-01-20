package com.rnfingerprint;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;

import com.facebook.react.bridge.Callback;

public class BiometricHandle extends BiometricPrompt.AuthenticationCallback {
    private Callback successCallback;
    private Callback failCallback;

    public BiometricHandle(Callback successCallback, Callback failCallback) {
        this.successCallback = successCallback;
        this.failCallback = failCallback;
    }

    @Override
    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);

        BiometricAuthModule.inProgress = false;
        failCallback.invoke("Not supported", BiometricAuthConstants.AUTHENTICATION_CANCELED);
    }

    @Override
    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);

        BiometricAuthModule.inProgress = false;
        successCallback.invoke("Successfully authenticated.");
    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();

        BiometricAuthModule.inProgress = false;
        failCallback.invoke("Not supported", BiometricAuthConstants.AUTHENTICATION_FAILED);
    }
}
