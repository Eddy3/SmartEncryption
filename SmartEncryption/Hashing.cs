using Sodium;

namespace SmartEncryption
{
    public class Hashing
    {
        public static string PasswordHash(string password, PasswordHash.Strength strength = Sodium.PasswordHash.Strength.Interactive)
        {
            return Sodium.PasswordHash.ScryptHashString(password, strength);
        }

        public static bool ValidatePasswordHash(string password, string hash)
        {
            return Sodium.PasswordHash.ScryptHashStringVerify(hash, password);
        }

        public static byte[] DeriveKey(byte[] password, byte[] salt, PasswordHash.Strength strength = Sodium.PasswordHash.Strength.Interactive)
        {
            return Sodium.PasswordHash.ScryptHashBinary(password, salt, strength);
        }

        public static byte[] FastHash(byte[] message)
        {
            return GenericHash.Hash(message, null, 32);
        }
    }
}
