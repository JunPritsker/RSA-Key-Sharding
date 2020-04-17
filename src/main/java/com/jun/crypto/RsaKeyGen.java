package com.jun.crypto;

import java.security.*;

import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

import java.util.Base64;
import java.util.List;

import javafx.util.Pair;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import javax.crypto.*;

public class RsaKeyGen{
    public static void main(String[] args) {

    }

    /**
     * @param encodedKey The encoded private key to reconstruct as a RSAPrivateKeySpec for verifying the moduli match
     * @return The RSAPrivateKeySpec
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static RSAPrivateKeySpec rebuildKeyFromData(byte[] encodedKey) throws NoSuchProviderException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec recoveredKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BCFIPS");
        RSAPrivateKeySpec privateKeySpec = null;
        try {
            PrivateKey recoveredPrivateKey = keyFactory.generatePrivate(recoveredKeySpec);
            privateKeySpec = keyFactory.getKeySpec(recoveredPrivateKey, RSAPrivateKeySpec.class);
        } catch (InvalidKeySpecException e) {
            System.out.println("[*]: Recovered secret is not an RSA private key");
            System.out.println("[*]: Failed to recover secret");
            System.exit(1);
        }
        return privateKeySpec;
    }

    /**
     * @param publicKey The PublicKey object to extra the RSAPublicKeySpec from
     * @return The RSAPublicKeySpec object that holds the modulus and public exponent of the PublicKey
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static RSAPublicKeySpec getPublicKeySpec (PublicKey publicKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BCFIPS");
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        return publicKeySpec;
    }

    /**
     * @param keySize The size of the key pair to create
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateKeyPair(int keySize) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = null;
        //Provide the bouncycastle FIPS provider
        Security.addProvider(new BouncyCastleFipsProvider());


        keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BCFIPS");
        //Initialize the generator with the RSA key size and public exponent (Fermat number F4)
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
        KeyPair keypair = keyPairGenerator.generateKeyPair();

        return keypair;
    }

    public static SecretKey generateAesKey(int keySize) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES", "BCFIPS");
        Security.addProvider(new BouncyCastleFipsProvider());
        //Need RNG for AES key
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BCFIPS");
        aesKeyGenerator.init(keySize, random);
        SecretKey encryptionKey = aesKeyGenerator.generateKey();
        return encryptionKey;
    }

    //
    public static AesEncryptedData aesEncrypt(byte[] data, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte [] iv = cipher.getIV();
        byte[] encryptedData = cipher.doFinal(data);
        return new AesEncryptedData(encryptedData, iv);
    }

    public static byte[] rsaEncrypt(byte [] data, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
    /**
     * @param publicKey The PublicKey object to print in the PKCS8 PEM base64-encoded format
     */
    public static void printRsaPublicKey(PublicKey publicKey){
        String formattedKeyData = Base64.getEncoder().encodeToString(publicKey.getEncoded()).replaceAll("(.{64})", "$1\n");
        System.out.print("-----BEGIN PUBLIC KEY-----\n");
        System.out.print(formattedKeyData);
        System.out.print("\n-----END PUBLIC KEY-----\n");
    }

    /**
     * @param privateKey The PrivateKey object to print in the PKCS8 PEM base64-encoded format
     */
    public static void printRsaPrivateKey(PrivateKey privateKey){
        String formattedKeyData = Base64.getEncoder().encodeToString(privateKey.getEncoded()).replaceAll("(.{64})", "$1\n");
        System.out.print("-----BEGIN PRIVATE KEY-----\n");
        System.out.print(formattedKeyData);
        System.out.print("\n-----END PRIVATE KEY-----\n");
    }
}