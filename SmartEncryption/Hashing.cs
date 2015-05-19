using Sodium;

namespace SmartEncryption
{
    public class Hashing
    {
        public static byte[] PasswordHash(byte[] password)
        {
            return PasswordHash(password, Sodium.PasswordHash.Strength.Interactive);
        }

        public static byte[] PasswordHash(byte[] password, PasswordHash.Strength strength)
        {
            var salt = Sodium.PasswordHash.GenerateSalt();
            return Sodium.PasswordHash.ScryptHashBinary(password, salt, strength);
        }

        public static byte[] FastHash(byte[] message)
        {
            return GenericHash.Hash(message, null, 32);
        }
    }
}
