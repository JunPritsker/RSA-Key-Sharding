package com.jun.crypto;

import com.codahale.shamir.Scheme;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import javax.xml.bind.DatatypeConverter;

import java.security.*;
import java.util.Map;
import java.util.Base64;

public class ShamirSecretSharingScheme {

    /**
     * @param privateKey The encoded PrivateKey to split into shares
     * @param n The total number of shares
     * @param k The minimum shares needed to recover the secret
     * @return A Map that maps each share number to its corresponding share data
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static Map<Integer, byte[]> splitSecret(byte[] privateKey, int n, int k) throws NoSuchProviderException, NoSuchAlgorithmException {

        Security.addProvider(new BouncyCastleFipsProvider());
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BCFIPS");
        final Scheme scheme = new Scheme(random, n, k);
        final byte[] secret = privateKey;
        final Map<Integer, byte[]> shares = scheme.split(secret);
        System.out.println("[*]: " + k + " of " + n + " sharing scheme");
//        for (Map.Entry<Integer, byte[]> share : shares.entrySet()){
//            //Base64 encode the shares so they're human readable/portable
//            System.out.println("Share " + share.getKey() + ":\n" + Base64.getEncoder().encodeToString(share.getValue()));
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            byte[] hash = digest.digest(share.getValue());
//            System.out.println(DatatypeConverter.printHexBinary(hash));
//        }
        return shares;
    }

    /**
     * @param shares The Map that maps each share number to its corresponding share data. The map doesn't need to hold all shares
     * @param n The total number of shares
     * @param k The minimum shares needed to recover the secret
     * @return The recovered secret base64 encoded for readability
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] recoverSecret(Map<Integer, byte[]> shares, int n, int k) throws NoSuchProviderException, NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BCFIPS");
        final Scheme scheme = new Scheme(random, n, k);
        final byte[] recoveredSecret = scheme.join(shares);
        return recoveredSecret;
    }
}