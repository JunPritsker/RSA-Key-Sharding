package com.jun.crypto;

import junit.framework.TestCase;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;


public class RsaKeyGenTest extends TestCase {

    public void testGenerateKeyPair() {
        KeyPair keyPair = null;
        try {
            keyPair = RsaKeyGen.generateKeyPair(2048);
            assertNotNull(keyPair);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
    public void testGetPublicKeySpec() {
        KeyPair keyPair = null;
        RSAPublicKeySpec publicKeySpec = null;
        try {
            keyPair = RsaKeyGen.generateKeyPair(2048);
            publicKeySpec = RsaKeyGen.getPublicKeySpec(keyPair.getPublic());
            assertNotNull(publicKeySpec);
        } catch (InvalidAlgorithmParameterException | InvalidKeySpecException | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}