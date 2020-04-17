package com.jun.crypto;

import javafx.util.Pair;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.CommandLineParser;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.security.*;

import java.math.BigInteger;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Map;
import java.util.Base64;
import java.util.HashMap;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;

import java.security.spec.RSAPrivateKeySpec;

public class App
{
    private static BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));

    public static void main( String[] args ) throws Exception {

        boolean errors = false;
        String keySize = null;
        String k = null;
        String n = null;

        do {

            // create Options object
            Options options = new Options();
            Option helpOption = new Option("help", "print this message");

            Option sizeOption = Option.builder("s")
                    .longOpt( "size" )
                    .desc( "The size of the RSA key pair to create. Valid options are 2048, 3072, 4096" )
                    .hasArg()
                    .argName( "SIZE" )
                    .build();

            Option mOption = Option.builder("k")
                    .longOpt( "k" )
                    .desc( "The k value for k of n" )
                    .hasArg()
                    .argName( "K" )
                    .build();

            Option nOption = Option.builder("n")
                    .longOpt( "n" )
                    .desc( "The n value for k of n" )
                    .hasArg()
                    .argName( "N" )
                    .build();

            options.addOption(sizeOption);
            options.addOption(mOption);
            options.addOption(nOption);

            CommandLineParser parser = new DefaultParser();
            CommandLine line = null;
            try {
                // parse the command line arguments
                line = parser.parse(options, args);

            } catch (ParseException e) {
                System.out.println("Error parsing arguments: " + e);
                errors = true;
                break;
            }
            // Check for valid key sizes
            if (line.hasOption("size")){
                String[] validSizes = {"2048", "3072", "4096"};
                keySize = line.getOptionValue("size");
                boolean valid = false;
                for (String size : validSizes){
                    if (keySize.equals(size)){
                        valid = true;
                        break;
                    }
                }
                if (!valid){
                    System.out.println("Key size must be 2048, 3072, or 4096");
                }
            }
            //Default to 4096 key size
            if (!line.hasOption("size")){
                keySize = "4096";
            }
            if (line.hasOption("k") && line.hasOption("n")) {

                k = line.getOptionValue("k");
                n = line.getOptionValue("n");

            }
            else {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("java -jar App.jar -k 2 -n 5 -size 4096", options);
                errors = true;
                break;
            }

        } while (false);
        if (errors) {
            System.out.println("[*]: Invalid commandline arguments");
            System.exit(1);
        }

        KeyPair keyPair = RsaKeyGen.generateKeyPair(Integer.parseInt(keySize));
        //Map a share to a secret key for encryption
        Map<Integer, SecretKey> shareToAESKey = new HashMap<>(Integer.parseInt(n));
        //Map a share to its public key for encrypting the secret key
        Map<Integer, KeyPair> shareToRSAKeyPair = new HashMap<>(Integer.parseInt(n));
        //Map a public key to the encrypted AES key
        Map<PublicKey, byte[]> publicKeyToAesKey= new HashMap<>(Integer.parseInt(n));

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        RsaKeyGen.printRsaPublicKey(publicKey);
        BigInteger publicKeyModulus = RsaKeyGen.getPublicKeySpec(publicKey).getModulus();
        System.out.print("[*]: Public key modulus:\n" + publicKeyModulus + "\n");
        int nInt = Integer.parseInt(n);
        int kInt = Integer.parseInt(k);
        Map<Integer, byte[]> shares = ShamirSecretSharingScheme.splitSecret(privateKey.getEncoded(), nInt, kInt); //Split the secret and print the shares

        byte[] encryptedData = null;
        byte[] encryptedAesKey = null;
        byte[] aesKeyIV = null;
        /*
        Generate a new RSA key pair and AES key for each share. Encrypt each share with the AES key and encrypt that AES key
        with the RSA public key. Use the RSA private key to decrypt the AES key later in order to recover the secret
        without revealing the secret to others.
        For now, print this data to the console instead of writing it to files. Normally the RSA key pairs would be provided to the program.
         */
        for (Map.Entry<Integer, byte[]> share : shares.entrySet()){
            SecretKey aesKey = RsaKeyGen.generateAesKey(256); //Generate an AES key
            KeyPair encryptionKeyPair = RsaKeyGen.generateKeyPair(Integer.parseInt(keySize));
            PublicKey publicEncryptionKey = encryptionKeyPair.getPublic();
            PrivateKey privateEncryptionKey = encryptionKeyPair.getPrivate();
            shareToAESKey.put(share.getKey(), aesKey); //Insert the AES key for this share into the Map
            shareToRSAKeyPair.put(share.getKey(), encryptionKeyPair); //Insert the key pair for this share into the Map
            AesEncryptedData data = RsaKeyGen.aesEncrypt(share.getValue(), aesKey); //Encrypt the data
            encryptedData = data.getEncryptedData();
            aesKeyIV = data.getIv();
            encryptedAesKey = RsaKeyGen.rsaEncrypt(aesKey.getEncoded(), publicEncryptionKey);
            publicKeyToAesKey.put(publicEncryptionKey, encryptedAesKey);
            //Printing the share defeats the purpose of encrypting the share but keeping this for demo purposes for now
            System.out.println("Share " + share.getKey() + ":\n" + Base64.getEncoder().encodeToString(share.getValue()));
//            String b64encryptedData = Base64.getEncoder().encodeToString(share.getValue());
//            System.out.println(b64encryptedData);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(share.getValue());
            System.out.println("SHA256 hash of share: \n" + DatatypeConverter.printHexBinary(hash));
            System.out.println("AES Encrypted share: \n" + Base64.getEncoder().encodeToString(encryptedData));
            System.out.println("RSA Encrypted AES Key: \n" + Base64.getEncoder().encodeToString(encryptedAesKey));
            System.out.println("AES KEY: \n" + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
            System.out.println("AES Key IV: \n" + DatatypeConverter.printHexBinary(aesKeyIV));
            RsaKeyGen.printRsaPrivateKey(privateEncryptionKey);
            System.out.println("---------------------------------------------------------------------");
        }
        privateKey.destroy(); //Destroy the private key and verify it's destroyed
        if (privateKey.isDestroyed()){
            System.out.println("[*]: Private key destroyed");
        }
        else{
            System.out.println("[*]: Private key was not destroyed");
            System.exit(1);
        }
        System.out.print("Enter the numbers of shares you'd like to use to recover the secret: ");
        int nRecoveryShares = Integer.parseInt(keyboard.readLine());
        Map<Integer, byte[]> recoveryShares = new HashMap<>(nInt);
        //Rebuild the mapping of shares
        for (int i = 0; i < nRecoveryShares; i++){
            System.out.print("Enter the share number: ");
            int shareNumber = Integer.parseInt(keyboard.readLine());
            System.out.print("Share " + shareNumber + ": ");
            String shareB64 = keyboard.readLine();
            byte[] share = Base64.getDecoder().decode(shareB64); //Convert the base64 encoded share back into bytes
            recoveryShares.put(shareNumber, share); //Insert the share into it's proper position in the array
        }
        byte[] recoveredSecret = ShamirSecretSharingScheme.recoverSecret(recoveryShares, nInt, kInt);
        //Turn the secret bytes into an RSAPrivateKeySpec so we can get its modulus.
        //This also checks if the recovered secret is a valid RSA private key
        RSAPrivateKeySpec recoveredKeySpec = RsaKeyGen.rebuildKeyFromData(recoveredSecret);
        BigInteger recoveredKeySpecModulus = recoveredKeySpec.getModulus();
        System.out.println("[*]: Private Key modulus: \n" + recoveredKeySpecModulus + "\n");

        if (recoveredKeySpecModulus == publicKeyModulus){
            System.out.println("[*]: Successful recovery: Recovered private key modulus matches the public key modulus");
        }
    }
}
