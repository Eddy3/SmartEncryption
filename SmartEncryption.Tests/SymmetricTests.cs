using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SmartEncryption.Tests
{
    [TestClass]
    public class SymmetricTests
    {
        [TestMethod]
        public void BasicCanDecryptStringTest()
        {
            const string PLAINTEXT = "SmartEncryption Sym Test";
            var key = Symmetric.GenerateKey();
            var cipher = Symmetric.Encrypt(PLAINTEXT, key);
            var plain = Symmetric.Decrypt(cipher, key);

            Assert.AreEqual(PLAINTEXT, Encoding.UTF8.GetString(plain));
        }
    }
}
