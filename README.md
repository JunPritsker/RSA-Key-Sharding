# RSA-Key-Sharding

This java demo creates an RSA key pair and shards the private key into k of n shares using codahale's implementation of Shamir's secret sharing algorithm [here](https://github.com/codahale/shamir). The user can then enter k or more shares to reconstitute the private key and verify the moduli.

# Build Instructions
1. Clone the repository: `git clone https://github.com/JunPritsker/RSA-Key-Sharding.git`
2. Run `mvn install`
3. Run `mvn exec:java -Dexec.mainClass=com.jun.crypto.App -Dexec.args="-k 2 -n 5 -size 4096"` to execute the program, changing the arguments as necessary.

# Usage Notes
 - To verify the output of the RSA/AES encrypted shares:
    - It is useful to use `base64 -D` to decode the string printed to the commandline.
    - It's also useful to pipe `base64 -D`'s output to `xxd -p` to convert it into hex.
    - [This](http://aes.online-domain-tools.com/) site can be used to decrypt the AES encrypted shares
    - To decrypt the RSA encrypted AES key
        1. Paste the RSA key into a file ex. `private.pem`
        2. Paste the RSA Encrypted AES key into a file
            1. type `cat encryptedAesKey.b64 | base64 -D > encryptedAesKey.bin` so that you have the encrypted blob's raw binary
            2. type `openssl rsautl -decrypt -in encryptedAesKey.bin -out aesKey -inkey private.pem` to decrypt the `encryptedAesKey.bin` file and write the AES Key to `aesKey`
  - All encrypted data and keys are written to the console in base64 encoding so that the user can see what the data is and can play with it/test it themselves.
  - In the future I will add functionality to write these keys/data to file and clean up the amount of console output