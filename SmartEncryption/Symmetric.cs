using System;
using System.Security.Cryptography;
using Security.Cryptography;
using System.IO;
using System.Text;
using Sodium;

namespace SmartEncryption
{
    public class Symmetric
    {
        private const int KEY_SIZE = 32;
        private const int NONCE_SIZE = 12;
        private const int TAG_SIZE = 16;
        private const byte VERSION = 0x01;
        private const int HEADER_LENGTH = 29;

        public static byte[] GenerateKey()
        {
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                var key = new byte[KEY_SIZE];
                rngCsp.GetBytes(key);
                return key;
            }
        }

        public static byte[] DeriveKey(string password, byte[] salt, PasswordHash.Strength strength = PasswordHash.Strength.Interactive)
        {
            return DeriveKey(Encoding.UTF8.GetBytes(password), salt, strength);
        }

        public static byte[] DeriveKey(byte[] password, byte[] salt, PasswordHash.Strength strength = PasswordHash.Strength.Interactive)
        {
            return Hashing.DeriveKey(password, salt, strength);
        }

        public static byte[] Encrypt(string plaintext, byte[] key)
        {
            return Encrypt(Encoding.UTF8.GetBytes(plaintext), key);
        }

        public static byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            if (key.Length != KEY_SIZE)
            {
                throw new ArgumentOutOfRangeException(nameof(key), "Invalid key size.");
            }

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
                    var record = new byte[HEADER_LENGTH + cipherText.Length];
                   
                    var offset = 1;
                    Buffer.BlockCopy(nonce, 0, record, offset, NONCE_SIZE);

                    offset += NONCE_SIZE;
                    Buffer.BlockCopy(authenticationTag, 0, record, offset, TAG_SIZE);

                    offset += TAG_SIZE;
                    Buffer.BlockCopy(cipherText, 0, record, offset, cipherText.Length);

                    return record;
                }
            }
        }

        public static byte[] Decrypt(byte[] record, byte[] key)
        {
            if (key.Length != KEY_SIZE)
            {
                throw new ArgumentOutOfRangeException(nameof(key), "Invalid key size.");
            }

            //check version
            if (record[0] != VERSION)
            {
                var offset = 1;
                var nonce = new byte[NONCE_SIZE];
                Buffer.BlockCopy(record, 1, nonce, 0, NONCE_SIZE);

                offset += NONCE_SIZE;
                var tag = new byte[TAG_SIZE];
                Buffer.BlockCopy(record, offset, tag, 0, TAG_SIZE);

                offset += TAG_SIZE;
                var cipherText = new byte[record.Length - HEADER_LENGTH];
                Buffer.BlockCopy(record, offset, cipherText, 0, record.Length - HEADER_LENGTH);

                using (var aes = new AuthenticatedAesCng())
                {
                    aes.CngMode = CngChainingMode.Gcm;
                    aes.KeySize = KEY_SIZE * 8; //bytes to bits
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
            else
            {
                //unsupported data versions
                throw new CryptographicException("Unsupported encrypted format.");
            }
        }

        private static byte[] GenerateNonce()
        {
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                var nonce = new byte[NONCE_SIZE];
                rngCsp.GetBytes(nonce);
                return nonce;
            }
        }
    }
}
