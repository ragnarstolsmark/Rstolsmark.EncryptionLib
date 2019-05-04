using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Rstolsmark.EncryptionLib
{
    public static class StringEncryptor
    {
        private static byte[] DeriveKey(string password, byte[] salt){
            return KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 32);
        }
        public static string Encrypt(string data, string password)
        {
            // generate a 128-bit salt using a secure PRNG
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            // derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
            byte[] key = DeriveKey(password, salt);
            using (Aes myAes = Aes.Create())
            {
                myAes.Key = key;
                byte[] encryptedData;
                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = myAes.CreateEncryptor();
                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(data);
                        }
                    }
                    encryptedData = msEncrypt.ToArray();
                }
                byte[] saltIVAndData = new byte[32 + encryptedData.Length];
                Buffer.BlockCopy(salt, 0, saltIVAndData, 0, 16);
                Buffer.BlockCopy(myAes.IV, 0, saltIVAndData, 16, 16);
                Buffer.BlockCopy(encryptedData, 0, saltIVAndData, 32, encryptedData.Length);
                return Convert.ToBase64String(saltIVAndData);
            }
        }

        public static string Decrypt(string encryptedData, string password)
        {
            byte[] saltIVAndData = Convert.FromBase64String(encryptedData);
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            byte[] data = new byte[saltIVAndData.Length - 32];
            Buffer.BlockCopy(saltIVAndData, 0, salt, 0, 16);
            Buffer.BlockCopy(saltIVAndData, 16, iv, 0, 16);
            Buffer.BlockCopy(saltIVAndData, 32, data, 0, saltIVAndData.Length - 32);
            byte[] key = DeriveKey(password, salt);
            using (Aes myAes = Aes.Create())
            {
                myAes.Key = key;
                myAes.IV = iv;
                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = myAes.CreateDecryptor();
                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(data))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and return them in a string.
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
