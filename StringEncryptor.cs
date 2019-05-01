using System;
using System.IO;
using System.Security.Cryptography;

namespace Rstolsmark.EncryptionLib
{
    public static class StringEncryptor
    {
        public static EncryptionResult Encrypt(string data, string key = null){
            using(Aes myAes = Aes.Create()){                
                if(!string.IsNullOrEmpty(key)){
                    myAes.Key = Convert.FromBase64String(key);
                }
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
                    encryptedData =  msEncrypt.ToArray();
                }
                byte[] iVAndData = new byte[16 + encryptedData.Length];
                Buffer.BlockCopy(myAes.IV, 0, iVAndData, 0, 16);
                Buffer.BlockCopy(encryptedData, 0, iVAndData, 16, encryptedData.Length);
                return new EncryptionResult{
                    Key = Convert.ToBase64String(myAes.Key),
                    EncryptedData = Convert.ToBase64String(iVAndData)
                };
            }
        }
         public static string Decrypt(string encryptedData, string key){
             using(Aes myAes = Aes.Create()){
                 myAes.Key = Convert.FromBase64String(key);
                 byte[] iVAndData = Convert.FromBase64String(encryptedData);
                 byte[] iv = new byte[16];
                 byte[] data = new byte[iVAndData.Length - 16];
                 Buffer.BlockCopy(iVAndData, 0, iv, 0, 16);
                 Buffer.BlockCopy(iVAndData, 16, data, 0, iVAndData.Length - 16);
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
