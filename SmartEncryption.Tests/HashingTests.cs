using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

namespace SmartEncryption.Tests
{
    [TestClass]
    public class HashingTests
    {
        [TestMethod]
        public void PasswordValidPass()
        {
            const string PASSWORD = "ThisIsANot SoRandomPasswordButItIsLongAndHasAspaceWayBackThere";
            var hash = Hashing.PasswordHash(PASSWORD);
            var result = Hashing.ValidatePasswordHash(PASSWORD, hash);

            Assert.IsTrue(result);
        }

        [TestMethod]
        public void PasswordInvalidPass()
        {
            const string PASSWORD = "ThisIsANot SoRandomPasswordButItIsLongAndHasAspaceWayBackThere";
            const string PASSWORD_BAD = "ThisIsNotTheRightPassword";
            var hash = Hashing.PasswordHash(PASSWORD);
            var result = Hashing.ValidatePasswordHash(PASSWORD_BAD, hash);

            Assert.IsFalse(result);
        }

        [TestMethod]
        public void PasswordValidPassSlow()
        {
            const string PASSWORD = "ThisIsANot SoRandomPasswordButItIsLongAndHasAspaceWayBackThere";
            var hash = Hashing.PasswordHash(PASSWORD, PasswordHash.Strength.Moderate);
            var result = Hashing.ValidatePasswordHash(PASSWORD, hash);

            Assert.IsTrue(result);
        }

        [TestMethod]
        public void DeriveKeySimpleTest()
        {
            const string PASSWORD = "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e00cc2890277f0fd3c622115772f7048adaebed86e";
            const string SALT = "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb";
            const long OUTPUT_LENGTH = 32;
            var hash1 = Hashing.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));
            var hash2 = Hashing.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));

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
            var hash1 = Hashing.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));
            var hash2 = Hashing.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));

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
            var hash1 = Hashing.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));
            var hash2 = Hashing.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));

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
            var hash1 = Hashing.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));
            var hash2 = Hashing.DeriveKey(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT));

            Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
            Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
            CollectionAssert.AreEqual(hash1, hash2);
        }

        [TestMethod]
        public void FastHashTest()
        {
            var expected = Utilities.HexToBinary("53e27925e5786abe74e6bb7004980a6a38a8da2478efa1b6b2ae73964cfe4876");
            var actual = Hashing.FastHash(Encoding.UTF8.GetBytes("Adam Caudill"));
            CollectionAssert.AreEqual(expected, actual);
        }
    }
}
