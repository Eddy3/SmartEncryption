using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SmartEncryption
{
    public static class KeyDerivation
    {
        private const int SALT_BYTES = 32;

        /// <summary>
        /// Creates a secure key based on a password.
        /// </summary>
        /// <param name="password">Password to be used to generate key.</param>
        /// <param name="salt">Salt to be used; <see cref="GenerateSalt"/>.</param>
        /// <returns>Secure derived key; 32 bytes.</returns>
        public static byte[] DeriveKey(string password, byte[] salt)
        {
            return Sodium.PasswordHash.ScryptHashBinary(Encoding.UTF8.GetBytes(password), salt);
        }

        /// <summary>
        /// Creates a secure key based on a password.
        /// </summary>
        /// <param name="password">Password to be used to generate key.</param>
        /// <param name="salt">Salt to be used; <see cref="GenerateSalt"/>.</param>
        /// <returns>Secure derived key; 32 bytes.</returns>
        public static byte[] DeriveKey(byte[] password, byte[] salt)
        {
            //hash the salt to ensure that it's the expected size of 32 bytes
            var hashedSalt = Hashing.FastHash(salt);

            return Sodium.PasswordHash.ScryptHashBinary(password, hashedSalt);
        }

        /// <summary>
        /// Generates a salt for use with <see cref="DeriveKey"/>
        /// </summary>
        /// <returns>32 random bytes</returns>
        public static byte[] GenerateSalt()
        {
            return Sodium.SodiumCore.GetRandomBytes(SALT_BYTES);
        }
    }
}
