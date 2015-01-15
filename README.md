# SmartEncryption

This is a library that provides a wrapper to the standard .NET encryption functionality, put together in a way that is designed to make it harder to make mistakes. The library is opinionated, has minimal options, and is designed to do the right thing; this is done at the cost of flexibility. This is the library you want to use if you aren’t sure what the right way to do something is, but want it to be right.

## Status

The project is still in the design phase; no code will be written until there is a solid design. 

## Design

**Symmetric Encryption** - AES-GCM, 256-bit key, 96-bit nonce, 128-bit tag. Performed via [CLR Security](https://clrsecurity.codeplex.com/), as .NET doesn’t currently have a native wrapper for this functionality. Data will be returned in the following format:

    version[1] || nonce[12] || tag[16] || data[length - 29]

**Symmetric Key & Nonce** - The nonce on all calls will be generated via [RNGCryptoServiceProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider%28v=vs.110%29.aspx). A `GenerateKey` method will also be provided that will use [RNGCryptoServiceProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider%28v=vs.110%29.aspx) to generate a secure random key.

**Symmetric Key Derivation** - To generate an encryption key from a password, a `DeriveKey` method will be provided that uses [scrypt](https://en.wikipedia.org/wiki/Scrypt) via [libsodium](https://github.com/jedisct1/libsodium) (via [libsodium-net](https://github.com/adamcaudill/libsodium-net)). Settings will be determined by the `Sodium.PasswordHash.Strength` value passed in.

**Asymmetric Encryption** - Will be performed via the [libsodium](https://github.com/jedisct1/libsodium) `crypto_box` method (Curve25519/XSalsa20/Poly1305).

Output format:

    version[1] || nonce[24] || data[length - 25]

**Asymmetric Key & Nonce** - The nonce on all calls will be generated via [libsodium](https://github.com/jedisct1/libsodium)’s `random_bytes` method. A `GenerateKey` method will also be provided that will use the `random_bytes` method to generate a secure random key.

**Asymmetric Key Derivation** - To generate an encryption key from a password, a `DeriveKey` method will be provided that uses [scrypt](https://en.wikipedia.org/wiki/Scrypt) via [libsodium](https://github.com/jedisct1/libsodium) (via [libsodium-net](https://github.com/adamcaudill/libsodium-net)). Settings will be determined by the `Sodium.PasswordHash.Strength` value passed in.

**Password Hashing** - To provide a safe means to hash passwords, [scrypt](https://en.wikipedia.org/wiki/Scrypt) will be used. Settings will be determined by the `Sodium.PasswordHash.Strength` value passed in.

**Fast Hashing** - To provide a high speed hashing algorithm, the `crypto_generichash` (BLAKE2b) method from [libsodium](https://github.com/jedisct1/libsodium) will be exposed.

## License

This project is licensed under the MIT license, see the LICENSE file for more details.
