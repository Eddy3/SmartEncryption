using System;
using System.Security.Cryptography;
using Security.Cryptography;
using System.IO;
using Sodium;

namespace SmartEncryption
{
    public class Symmetric
    {
        private const int KEY_SIZE = 256;
        private const int KEY_SIZE_BYTES = 32;
        private const int NONCE_SIZE = 96;
        private const int NONCE_SIZE_BYTES = 12;
        private const int TAG_SIZE = 128;
        private const int TAG_SIZE_BYTES = 16;
        private const byte VERSION = 0x01;
        private const int HEADER_LENGTH = 29;

        public static byte[] GenerateNonce()
        {
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                var nonce = new byte[NONCE_SIZE_BYTES];
                rngCsp.GetBytes(nonce);
                return nonce;
            }
        }

        public static byte[] GenerateKey()
        {
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                var key = new byte[KEY_SIZE_BYTES];
                rngCsp.GetBytes(key);
                return key;
            }
        }

        public static byte[] DeriveKey(byte[] password, byte[] salt, PasswordHash.Strength strength = PasswordHash.Strength.Interactive)
        {
            return Hashing.DeriveKey(password, salt, strength);
        }

        public static byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            var nonce = GenerateNonce();
            using (var aes = new AuthenticatedAesCng())
            {
                aes.CngMode = CngChainingMode.Gcm;
                aes.Key = key;
                aes.IV = nonce;

                using (var ms = new MemoryStream())
                using (var encryptor = aes.CreateAuthenticatedEncryptor())
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(plaintext, 0, plaintext.Length);
                    cs.FlushFinalBlock();
                    var cipherText = ms.ToArray();
                    var authenticationTag = encryptor.GetTag();
                    var blob = new byte[HEADER_LENGTH + cipherText.Length];
                   
                    var offset = 1;
                    Buffer.BlockCopy(nonce, 0, blob, offset, NONCE_SIZE_BYTES);

                    offset += NONCE_SIZE_BYTES;
                    Buffer.BlockCopy(authenticationTag, 0, blob, offset, TAG_SIZE_BYTES);

                    offset += TAG_SIZE_BYTES;
                    Buffer.BlockCopy(cipherText, 0, blob, offset, cipherText.Length);

                    return blob;
                }
            }
        }

        public static byte[] Decrypt(byte[] blob, byte[] key)
        {
            var offset = 1;
            var nonce = new byte[NONCE_SIZE_BYTES];
            Buffer.BlockCopy(blob, 1, nonce, 0, NONCE_SIZE_BYTES);

            offset += NONCE_SIZE_BYTES;
            var tag = new byte[TAG_SIZE_BYTES];
            Buffer.BlockCopy(blob, offset, tag, 0, TAG_SIZE_BYTES);

            offset += TAG_SIZE_BYTES;
            var cipherText = new byte[blob.Length - HEADER_LENGTH];
            Buffer.BlockCopy(blob, offset, cipherText, 0, blob.Length - HEADER_LENGTH);

            using (var aes = new AuthenticatedAesCng())
            {
                aes.CngMode = CngChainingMode.Gcm;
                aes.KeySize = KEY_SIZE;
                aes.Key = key;
                aes.IV = nonce;
                aes.Tag = tag;

                using (var ms = new MemoryStream())
                using (var encryptor = aes.CreateDecryptor())
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(cipherText, 0, cipherText.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }
    }
}
