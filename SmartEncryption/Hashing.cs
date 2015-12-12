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

        public static byte[] FastHash(byte[] message)
        {
            return GenericHash.Hash(message, null, 32);
        }
    }
}
