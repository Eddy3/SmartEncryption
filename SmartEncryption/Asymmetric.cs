using Sodium;

namespace SmartEncryption
{
    public class Asymmetric
    {
        private const int NONCE_SIZE_BYTES = 24;
        private const byte VERSION = 0x01;

        public static byte[] GenerateNonce()
        {
            return Sodium.PublicKeyBox.GenerateNonce();
        }

        public static AsymmetricKeyPair GenerateKeyPair()
        {
            return new AsymmetricKeyPair(Sodium.PublicKeyBox.GenerateKeyPair());
        }

        public static byte[] Encrypt(byte[] message, byte[] privateKey, byte[] publicKey)
        {
            byte[] nonce = GenerateNonce();
            byte[] cipherText = Sodium.PublicKeyBox.Create(message, nonce, privateKey, publicKey);
            byte[] blob = new byte[25 + cipherText.Length];
            blob[0] = VERSION;
            int offset = 1;
            System.Buffer.BlockCopy(nonce, 0, blob, offset, NONCE_SIZE_BYTES);
            offset += NONCE_SIZE_BYTES;
            System.Buffer.BlockCopy(cipherText, 0, blob, offset, cipherText.Length);
            return blob;
        }

        public static byte[] Decrypt(byte[] blob, byte[] privateKey, byte[] publicKey)
        {
            int offset = 1;
            byte[] nonce = new byte[NONCE_SIZE_BYTES];
            System.Buffer.BlockCopy(blob, 1, nonce, 0, NONCE_SIZE_BYTES);
            offset += NONCE_SIZE_BYTES;
            byte[] cipherText = new byte[blob.Length - 25];
            System.Buffer.BlockCopy(blob, offset, cipherText, 0, blob.Length - 25);
            return Sodium.PublicKeyBox.Open(cipherText, nonce, privateKey, publicKey);
        }
    }
}
