package com.wimobile.efecty.core.keystore;

import android.util.Base64;

import androidx.annotation.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CipherWrapper {

    private static final String TRANSFORMATION_ASYMMETRIC = "RSA/ECB/PKCS1Padding";

    private Cipher cipher;

    public CipherWrapper(String transformation) {
        try {
            cipher = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    public CipherWrapper() {
        try {
            cipher = Cipher.getInstance(TRANSFORMATION_ASYMMETRIC);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    public Cipher getCipher() {
        return cipher;
    }

    @Nullable
    public String encrypt(String data, Key key) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] bytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeToString(bytes, Base64.DEFAULT);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Nullable
    public String decrypt(String data, Key key) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] encryptedData = Base64.decode(data, Base64.DEFAULT);
            byte[] decodedData = cipher.doFinal(encryptedData);
            return new String(decodedData);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return null;
    }
}
