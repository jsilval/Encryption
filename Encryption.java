package com.wimobile.efecty.core.keystore;


import android.content.Context;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;

public final class Encryption {

    private static Encryption INSTANCE;

    private CipherWrapper cipherWrapper;

    private KeyPair masterKey;

    private Encryption(Context context) {
        KeyStoreWrapper keyStoreWrapper = new KeyStoreWrapper(context);
        try {
            keyStoreWrapper.createAndroidKeyStoreAsymmetricKey("MASTER_KEY");
            masterKey = keyStoreWrapper.getAndroidKeyStoreAsymmetricKeyPair("MASTER_KEY");
            cipherWrapper = new CipherWrapper("RSA/ECB/PKCS1Padding");
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                UnrecoverableKeyException | KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public static Encryption getInstance(Context context) {
        if (INSTANCE == null) {
            INSTANCE = new Encryption(context);
        }
        return INSTANCE;
    }

    public String encrypt(String message) {
        return cipherWrapper.encrypt(message, masterKey.getPublic());
    }

    public String decrypt(String message) {
        return cipherWrapper.decrypt(message, masterKey.getPrivate());
    }
}
