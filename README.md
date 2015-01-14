# SmartEncryption

This is a library that provides a wrapper to the standard .NET encryption functionality, put together in a way that is designed to make it harder to make mistakes. The library is opinionated, has minimal options, and is designed to do the right thing; this is done at the cost of flexibility. This is the library you want to use if you aren’t sure what the right way to do something is, but want it to be right.

## Status

The project is still in the design phase; no code will be written until there is a solid design. 

## Design

**Symmetric Encryption** - AES-GCM, 256-bit key, 96-bit nonce, 128-bit tag. Performed via [CLR Security](https://clrsecurity.codeplex.com/), as .NET doesn’t currently have a native wrapper for this functionality. Data will be returned in the following format:

    nonce[12] || tag[16] || data[length - 28]

**Symmetric Key & Nonce** - The nonce on all calls will be generated via [RNGCryptoServiceProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider%28v=vs.110%29.aspx). A `GenerateKey` method will also be provided that will use [RNGCryptoServiceProvider](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider%28v=vs.110%29.aspx) to generate a secure random key.

**Symmetric Key Derivation** - To generate an encryption key from a password, a `DeriveKey` method will be provided that uses PBKDF2 (via [Rfc2898DeriveBytes](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rfc2898derivebytes%28v=vs.110%29.aspx) - which is based on [HMACSHA1](http://msdn.microsoft.com/en-us/library/system.security.cryptography.hmacsha1%28v=vs.110%29.aspx)). The integration count will be based on the following enumeration:

* `SecurityLevel.Low` = 10,000
* `SecurityLevel.Medium` = 50,000
* `SecurityLevel.High` = 100,000

## License

This project is licensed under the MIT license, see the LICENSE file for more details.
