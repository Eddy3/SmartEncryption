using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sodium;

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

        [TestMethod]
        public void BasicCanDecryptTest()
        {
            const string PLAINTEXT = "SmartEncryption Sym Test";
            var key = Symmetric.GenerateKey();
            var cipher = Symmetric.Encrypt(Encoding.UTF8.GetBytes(PLAINTEXT), key);
            var plain = Symmetric.Decrypt(cipher, key);

            Assert.AreEqual(PLAINTEXT, Encoding.UTF8.GetString(plain));
        }

        [TestMethod]
        public void DeriveKeyStringIsDeterministicTest()
        {
            const string PASSWORD = "Password1";
            const string SALT = "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb";
            var val1 = Symmetric.DeriveKey(PASSWORD, Utilities.HexToBinary(SALT));
            var val2 = Symmetric.DeriveKey(PASSWORD, Utilities.HexToBinary(SALT));

            CollectionAssert.AreEqual(val1, val2);
        }
    }
}
