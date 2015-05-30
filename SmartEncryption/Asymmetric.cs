using System;
using System.Security.Cryptography;
using Sodium;

namespace SmartEncryption
{
    public class Asymmetric
    {
        private const int NONCE_SIZE_BYTES = 24;
        private const byte VERSION = 0x01;

        public static AsymmetricKeyPair GenerateKeyPair()
        {
            return new AsymmetricKeyPair(PublicKeyBox.GenerateKeyPair());
        }

        public static byte[] Encrypt(byte[] message, byte[] privateKey, byte[] publicKey)
        {
            var nonce = GenerateNonce();
            var cipherText = PublicKeyBox.Create(message, nonce, privateKey, publicKey);
            var record = new byte[25 + cipherText.Length];

            record[0] = VERSION;

            var offset = 1;
            Buffer.BlockCopy(nonce, 0, record, offset, NONCE_SIZE_BYTES);

            offset += NONCE_SIZE_BYTES;
            Buffer.BlockCopy(cipherText, 0, record, offset, cipherText.Length);

            return record;
        }

        public static byte[] Decrypt(byte[] record, byte[] privateKey, byte[] publicKey)
        {
            //validate that the version header is right
            if (record[0] == VERSION)
            {
                var offset = 1;
                var nonce = new byte[NONCE_SIZE_BYTES];
                Buffer.BlockCopy(record, 1, nonce, 0, NONCE_SIZE_BYTES);

                offset += NONCE_SIZE_BYTES;
                var cipherText = new byte[record.Length - 25];
                Buffer.BlockCopy(record, offset, cipherText, 0, record.Length - 25);

                return PublicKeyBox.Open(cipherText, nonce, privateKey, publicKey);
            }
            else
            {
                //unsupported data versions
                throw new CryptographicException("Unsupported encrypted format.");
            }
        }

        private static byte[] GenerateNonce()
        {
            return PublicKeyBox.GenerateNonce();
        }
    }
}
