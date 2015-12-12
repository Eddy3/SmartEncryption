using Sodium;

namespace SmartEncryption
{
    public class Hashing
    {
        public static string PasswordHash(string password)
        {
            return Sodium.PasswordHash.ScryptHashString(password);
        }

        public static bool ValidatePasswordHash(string password, string hash)
        {
            return Sodium.PasswordHash.ScryptHashStringVerify(hash, password);
        }

        public static byte[] DeriveKey(byte[] password, byte[] salt)
        {
            //hash the salt to ensure that it's the expected size of 32 bytes
            var hashedSalt = FastHash(salt);

            return Sodium.PasswordHash.ScryptHashBinary(password, hashedSalt);
        }

        public static byte[] FastHash(byte[] message)
        {
            return GenericHash.Hash(message, null, 32);
        }
    }
}
