# RSA-Key-Sharding

This java demo creates an RSA key pair and shards the private key into k of n shares using codahale's implementation of Shamir's secret sharing algorithm [here](https://github.com/codahale/shamir). The user can then enter k or more shares to reconstitute the private key and verify the moduli.

# Build Instructions
1. Clone the repository: `git clone https://github.com/JunPritsker/RSA-Key-Sharding.git`
2. Run `mvn install`
3. Run `mvn exec:java -Dexec.mainClass=com.jun.crypto.App -Dexec.args="-k 2 -n 5 -size 4096"` to execute the program, changing the arguments as necessary.
