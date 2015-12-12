using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

namespace SmartEncryption.Tests
{
    [TestClass]
    public class KeyDerivationTests
    {
        [TestMethod]
        public void DeriveKeySimpleTest()
        {
            const string PASSWORD = "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e00cc2890277f0fd3c622115772f7048adaebed86e";
            const string SALT = "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb";
            const long OUTPUT_LENGTH = 32;
            var hash1 = KeyDerivation.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));
            var hash2 = KeyDerivation.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));

            Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
            Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
            CollectionAssert.AreEqual(hash1, hash2);
        }

        [TestMethod]
        public void DeriveKeyShortPassTest()
        {
            const string PASSWORD = "e125cee61c8cb7";
            const string SALT = "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb";
            const long OUTPUT_LENGTH = 32;
            var hash1 = KeyDerivation.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));
            var hash2 = KeyDerivation.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));

            Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
            Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
            CollectionAssert.AreEqual(hash1, hash2);
        }

        [TestMethod]
        public void DeriveKeyLargeSalt()
        {
            const string PASSWORD = "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e00cc2890277f0fd3c622115772f7048adaebed86e";
            const string SALT = "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb";
            const long OUTPUT_LENGTH = 32;
            var hash1 = KeyDerivation.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));
            var hash2 = KeyDerivation.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));

            Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
            Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
            CollectionAssert.AreEqual(hash1, hash2);
        }

        [TestMethod]
        public void DeriveKeySmallSalt()
        {
            const string PASSWORD = "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e00cc2890277f0fd3c622115772f7048adaebed86e";
            const string SALT = "4407";
            const long OUTPUT_LENGTH = 32;
            var hash1 = KeyDerivation.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));
            var hash2 = KeyDerivation.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));

            Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
            Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
            CollectionAssert.AreEqual(hash1, hash2);
        }
    }
}
