using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SmartEncryption;

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
    }
}
