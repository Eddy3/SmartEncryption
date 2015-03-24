using Sodium;

namespace SmartEncryption
{
    public class Hashing
    {

        public static byte[] PasswordHash(byte[] password)
        {
            return PasswordHash(password, Sodium.PasswordHash.Strength.Interactive);
        }

        public static byte[] PasswordHash(byte[] password, Sodium.PasswordHash.Strength strength)
        {
            byte[] salt = Sodium.PasswordHash.GenerateSalt();
            return Sodium.PasswordHash.ScryptHashBinary(password, salt, strength);
        }

        public static byte[] FastHash(byte[] message)
        {
            return Sodium.GenericHash.Hash(message, null, 32);
        }
    }
}
