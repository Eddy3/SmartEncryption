using System.Security.Cryptography;
using Security.Cryptography;
using System.IO;
using System;

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

        public static byte[] GenerateNonce()
        {
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                byte[] nonce = new byte[NONCE_SIZE_BYTES];
                rngCsp.GetBytes(nonce);
                return nonce;
            }
        }

        public static byte[] GenerateKey()
        {
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[KEY_SIZE_BYTES];
                rngCsp.GetBytes(key);
                return key;
            }
            
        }

        public static byte[] DeriveKey(byte[] password)
        {
            return Hashing.PasswordHash(password);
        }

        public static byte[] DeriveKey(byte[] password, Sodium.PasswordHash.Strength strength)
        {
            return Hashing.PasswordHash(password, strength);
        }
        public static byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            byte[] nonce = GenerateNonce();
            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                aes.CngMode = CngChainingMode.Gcm;
                aes.Key = key;
                aes.IV = nonce;

                using (MemoryStream ms = new MemoryStream())
                using (IAuthenticatedCryptoTransform encryptor = aes.CreateAuthenticatedEncryptor())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(plaintext, 0, plaintext.Length);
                    cs.FlushFinalBlock();
                    byte[] cipherText = ms.ToArray();
                    byte[] authenticationTag = encryptor.GetTag();
                    byte[] blob = new byte[29 + cipherText.Length];
                    int writeOffset = 1;
                    blob[0] = VERSION;
                    System.Buffer.BlockCopy(nonce, 0, blob, writeOffset, NONCE_SIZE_BYTES);
                    writeOffset += NONCE_SIZE_BYTES;
                    System.Buffer.BlockCopy(authenticationTag, 0, blob, writeOffset, TAG_SIZE_BYTES);
                    writeOffset += TAG_SIZE_BYTES;
                    System.Buffer.BlockCopy(cipherText, 0, blob, writeOffset, cipherText.Length);
                    return blob;
                }
            }
        }

        public static byte[] Decrypt(byte[] blob, byte[] key)
        {
            int offset = 1;
            byte[] nonce = new byte[NONCE_SIZE_BYTES];
            System.Buffer.BlockCopy(blob, 1, nonce, 0, NONCE_SIZE_BYTES);
            offset += NONCE_SIZE_BYTES;
            byte[] tag = new byte[TAG_SIZE_BYTES];
            System.Buffer.BlockCopy(blob, offset, tag, 0, TAG_SIZE_BYTES);
            offset += TAG_SIZE_BYTES;
            byte[] cipherText = new byte[blob.Length - 29];
            System.Buffer.BlockCopy(blob, offset, cipherText, 0, blob.Length - 29);
            using (AuthenticatedAesCng aes = new AuthenticatedAesCng()) 
            {
                aes.CngMode = CngChainingMode.Gcm;
                aes.KeySize = KEY_SIZE;
                aes.Key = key;
                aes.IV = nonce;
                aes.Tag = tag;

                using (MemoryStream ms = new MemoryStream())
                using (ICryptoTransform encryptor = aes.CreateDecryptor())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(cipherText, 0, cipherText.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

    }
}
