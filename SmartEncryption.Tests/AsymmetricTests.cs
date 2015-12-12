using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SmartEncryption.Tests
{
    [TestClass]
    public class AsymmetricTests
    {
        [TestMethod]
        public void BasicCanDecryptTest()
        {
            const string PLAINTEXT = "This is a test of the SmartEncryption system...";
            var senderKeys = Asymmetric.GenerateKeyPair();
            var recipKeys = Asymmetric.GenerateKeyPair();

            var cipher = Asymmetric.Encrypt(Encoding.UTF8.GetBytes(PLAINTEXT), senderKeys.PrivateKey,
                recipKeys.PublicKey);
            var plain = Asymmetric.Decrypt(cipher, recipKeys.PrivateKey, senderKeys.PublicKey);

            Assert.AreEqual(PLAINTEXT, Encoding.UTF8.GetString(plain));
        }
    }
}
