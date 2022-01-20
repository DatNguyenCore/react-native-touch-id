package com.rnfingerprint;

import android.annotation.TargetApi;
import android.app.Activity;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.widget.Toast;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class BiometricAuthModule extends ReactContextBaseJavaModule implements LifecycleEventListener {

    private boolean isAppActive;
    private BiometricManager biometricManager;
    private Executor executor;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;

    protected String biometricKeyAlias = "biometric_key";
    private static final String KEY_STORE_INSTANCE = "AndroidKeyStore";

    private String dialogTitle = "Biometric authentication";
    private String sensorDescription = "Authenticate your app";
    private String cancelText = "Back";

    public static boolean inProgress = false;

    public BiometricAuthModule(final ReactApplicationContext reactContext) {
        super(reactContext);

        reactContext.addLifecycleEventListener(this);
    }

    private BiometricManager getBiometricManager() {
        if (biometricManager != null) {
            return biometricManager;
        }

        final Activity activity = getCurrentActivity();
        if (activity == null) {
            return null;
        }

        biometricManager = BiometricManager.from(activity);
        return biometricManager;
    }

    @Override
    public String getName() {
        return "FingerprintAuth";
    }

    @ReactMethod
    public void isSupported(final Callback reactErrorCallback, final Callback reactSuccessCallback) {
        final Activity activity = getCurrentActivity();
        if (activity == null) {
            return;
        }

        int result = isBiometricAuthAvailable();
        if (result == BiometricAuthConstants.IS_SUPPORTED) {
            reactSuccessCallback.invoke("Is supported.");
        } else {
            reactErrorCallback.invoke("Not supported.", result);
        }
    }

    private boolean deleteBiometricKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(this.KEY_STORE_INSTANCE);
            keyStore.load(null);

            keyStore.deleteEntry(biometricKeyAlias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @ReactMethod
    public void createKeys(final Callback reactErrorCallback, final Callback reactSuccessCallback) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                deleteBiometricKey();
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, this.KEY_STORE_INSTANCE);
                KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(biometricKeyAlias, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                        .setUserAuthenticationRequired(true)
                        .build();
                keyPairGenerator.initialize(keyGenParameterSpec);

                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                PublicKey publicKey = keyPair.getPublic();
                byte[] encodedPublicKey = publicKey.getEncoded();
                String publicKeyString = Base64.encodeToString(encodedPublicKey, Base64.DEFAULT);
                publicKeyString = publicKeyString.replaceAll("\r", "").replaceAll("\n", "");

                WritableMap resultMap = new WritableNativeMap();
                resultMap.putString("publicKey", publicKeyString);
                reactSuccessCallback.invoke(resultMap);
            } else {
                reactErrorCallback.invoke("Cannot generate keys on android versions below 6.0", "Cannot generate keys on android versions below 6.0");
            }
        } catch (Exception e) {
            reactErrorCallback.invoke("Error generating public private keys: " + e.getMessage(), "Error generating public private keys");
        }
    }

    @ReactMethod
    public void biometricKeysExist(final Callback reactErrorCallback, final Callback reactSuccessCallback) {
        try {
            boolean doesBiometricKeyExist = doesBiometricKeyExist();
            reactSuccessCallback.invoke(doesBiometricKeyExist);
        } catch (Exception e) {
            reactErrorCallback.invoke("Error checking if biometric key exists: " + e.getMessage(), "Error checking if biometric key exists: " + e.getMessage());
        }
    }

    private boolean doesBiometricKeyExist() {
        try {
            KeyStore keyStore = KeyStore.getInstance(this.KEY_STORE_INSTANCE);
            keyStore.load(null);

            return keyStore.containsAlias(biometricKeyAlias);
        } catch (Exception e) {
            return false;
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    @ReactMethod
    public void authenticate(final String reason, final ReadableMap config, final Callback reactErrorCallback, final Callback reactSuccessCallback) {
        if (config.hasKey("title")) {
            dialogTitle = config.getString("title");
        }
        if (config.hasKey("sensorDescription")) {
            sensorDescription = config.getString("sensorDescription");
        }
        if (config.hasKey("cancelText")) {
            cancelText = config.getString("cancelText");
        }

        final Activity activity = getCurrentActivity();
        if (inProgress || !isAppActive || activity == null) {
            return;
        }
        inProgress = true;

        if (getCurrentActivity() == null) {
            return;
        }

        if (!isAppActive) {
            inProgress = false;
            return;
        }

        int availableResult = isBiometricAuthAvailable();
        if (availableResult != BiometricAuthConstants.IS_SUPPORTED) {
            inProgress = false;
            reactErrorCallback.invoke("Not supported", availableResult);
            return;
        }

        UiThreadUtil.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    BiometricHandle authCallback = new BiometricHandle(reactSuccessCallback, reactErrorCallback);
                    FragmentActivity fragmentActivity = (FragmentActivity) getCurrentActivity();
                    Executor executor = Executors.newSingleThreadExecutor();
                    BiometricPrompt biometricPrompt = new BiometricPrompt(fragmentActivity, executor, authCallback);

                    Signature signature = Signature.getInstance("SHA256withRSA");
                    KeyStore keyStore = KeyStore.getInstance(BiometricAuthModule.this.KEY_STORE_INSTANCE);
                    keyStore.load(null);

                    PrivateKey privateKey = (PrivateKey) keyStore.getKey(biometricKeyAlias, null);
                    signature.initSign(privateKey);

                    BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);

                    promptInfo = new BiometricPrompt.PromptInfo.Builder()
                            .setTitle(dialogTitle)
                            .setSubtitle(sensorDescription)
                            .setNegativeButtonText(cancelText)
                            .build();

                    biometricPrompt.authenticate(promptInfo, cryptoObject);
                } catch (Exception e) {
                    Toast.makeText(getReactApplicationContext(), e.getMessage(), Toast.LENGTH_SHORT).show();
                    reactErrorCallback.invoke("Not supported", BiometricAuthConstants.NOT_AVAILABLE);
                }
            }
        });
    }

    private int isBiometricAuthAvailable() {
        if (android.os.Build.VERSION.SDK_INT < 23) {
            return BiometricAuthConstants.NOT_SUPPORTED;
        }

        final Activity activity = getCurrentActivity();
        if (activity == null) {
            return BiometricAuthConstants.NOT_AVAILABLE; // we can't do the check
        }

        final BiometricManager biometricManager = getBiometricManager();

        switch (biometricManager.canAuthenticate()) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                return BiometricAuthConstants.IS_SUPPORTED;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                return BiometricAuthConstants.NOT_PRESENT;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                return BiometricAuthConstants.NOT_AVAILABLE;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                return BiometricAuthConstants.NOT_ENROLLED;
        }

        return BiometricAuthConstants.IS_SUPPORTED;
    }

    @Override
    public void onHostResume() {
        isAppActive = true;
    }

    @Override
    public void onHostPause() {
        isAppActive = false;
    }

    @Override
    public void onHostDestroy() {
        isAppActive = false;
    }
}
