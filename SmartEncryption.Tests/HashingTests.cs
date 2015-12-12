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
        public void FastHashTest()
        {
            var expected = Utilities.HexToBinary("53e27925e5786abe74e6bb7004980a6a38a8da2478efa1b6b2ae73964cfe4876");
            var actual = Hashing.FastHash(Encoding.UTF8.GetBytes("Adam Caudill"));
            CollectionAssert.AreEqual(expected, actual);
        }
    }
}
