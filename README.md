# SmartEncryption

An opinionated, secure-by-default, does-the-right-thing modern cryptography library.

## Status

Experimental. As this library is still in development, it shouldn't be used for production systems. A design and implementation audit is being planned.

## Design

**Symmetric Encryption** - 

AES-GCM, 256-bit key, 96-bit nonce, 128-bit tag. Performed via [CLR Security](https://clrsecurity.codeplex.com/), as .NET doesn't currently have a native wrapper for this functionality. Data will be returned in the following format:

    version[1] || nonce[12] || tag[16] || data[length - 29]

**Asymmetric Encryption** - `SmartEncryption.Asymmetric.Encrypt()`

Curve25519/XSalsa20/Poly1305 based public-key encryption. Random keys can be generated via the `SmartEncryption.Asymmetric.GenerateKeyPair()` method.

Output format:

    version[1] || nonce[24] || data[length - 25]

**Fast Hashing** - `SmartEncryption.Hashing.FastHash()`

High-speed hashing via [BLAKE2b](https://blake2.net/).

**Password Hashing** `SmartEncryption.Hashing.PasswordHash()`

Safe password hashing using [scrypt](https://en.wikipedia.org/wiki/Scrypt). Hashes are returned as a string that can be safely stored in a database, and can be verified via the `SmartEncryption.Hashing.ValidatePasswordHash()` function.

**Key Derivation** - `SmartEncryption.KeyDerivation.DeriveKey()`

In addition to password hashing, [scrypt](https://en.wikipedia.org/wiki/Scrypt) is exposed for use as a secure key derivation function.

## Libraries

This library depends on:

 * [libsodium](https://github.com/jedisct1/libsodium)
 * [libsodium-net](https://github.com/adamcaudill/libsodium-net)
 * [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145)
 * .NET Framework 4.5.2


## License

This project is licensed under the MIT license, see the LICENSE file for more details.
