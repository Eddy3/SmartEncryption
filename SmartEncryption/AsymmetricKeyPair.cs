using Sodium;

namespace SmartEncryption
{
    public class AsymmetricKeyPair
    {
        private readonly KeyPair _keyPair;

        public byte[] PrivateKey => _keyPair.PrivateKey;

        public byte[] PublicKey => _keyPair.PublicKey;

        public AsymmetricKeyPair(KeyPair keyPair)
        {
            _keyPair = keyPair;
        }
    }
}
