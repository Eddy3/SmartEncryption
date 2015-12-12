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

        public static byte[] DeriveKey(byte[] password, byte[] salt)
        {
            //hash the salt to ensure that it's the expected size of 32 bytes
            var hashedSalt = Hashing.FastHash(salt);

            return Sodium.PasswordHash.ScryptHashBinary(password, hashedSalt);
        }

        public static byte[] GenerateSalt()
        {
            return Sodium.SodiumCore.GetRandomBytes(SALT_BYTES);
        }
    }
}
