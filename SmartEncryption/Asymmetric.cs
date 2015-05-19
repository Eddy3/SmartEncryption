using System;
using Sodium;

namespace SmartEncryption
{
    public class Asymmetric
    {
        private const int NONCE_SIZE_BYTES = 24;
        private const byte VERSION = 0x01;

        public static byte[] GenerateNonce()
        {
            return PublicKeyBox.GenerateNonce();
        }

        public static AsymmetricKeyPair GenerateKeyPair()
        {
            return new AsymmetricKeyPair(PublicKeyBox.GenerateKeyPair());
        }

        public static byte[] Encrypt(byte[] message, byte[] privateKey, byte[] publicKey)
        {
            var nonce = GenerateNonce();
            var cipherText = PublicKeyBox.Create(message, nonce, privateKey, publicKey);
            var blob = new byte[25 + cipherText.Length];
            blob[0] = VERSION;
            var offset = 1;

            Buffer.BlockCopy(nonce, 0, blob, offset, NONCE_SIZE_BYTES);
            offset += NONCE_SIZE_BYTES;
            Buffer.BlockCopy(cipherText, 0, blob, offset, cipherText.Length);

            return blob;
        }

        public static byte[] Decrypt(byte[] blob, byte[] privateKey, byte[] publicKey)
        {
            var offset = 1;
            var nonce = new byte[NONCE_SIZE_BYTES];
            Buffer.BlockCopy(blob, 1, nonce, 0, NONCE_SIZE_BYTES);

            offset += NONCE_SIZE_BYTES;
            var cipherText = new byte[blob.Length - 25];
            Buffer.BlockCopy(blob, offset, cipherText, 0, blob.Length - 25);

            return PublicKeyBox.Open(cipherText, nonce, privateKey, publicKey);
        }
    }
}
