# RSA-Key-Sharding

This java demo creates an RSA key pair and shards the private key into k of n shares using codahale's implementation of Shamir's secret sharing algorithm [here](https://github.com/codahale/shamir). The user can then enter k or more shares to reconstitute the private key and verify the moduli.

# Build Instructions
1.