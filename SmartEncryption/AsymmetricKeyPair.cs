using Sodium;

namespace SmartEncryption
{
  public class AsymmetricKeyPair
  {
    private readonly KeyPair _keyPair;

    public byte[] PrivateKey
    {
      get { return _keyPair.PrivateKey; }
    }

    public byte[] PublicKey
    {
      get { return _keyPair.PublicKey; }
    }

    public AsymmetricKeyPair(KeyPair keyPair)
    {
      _keyPair = keyPair;
    }
  }
}
