using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Security.Cryptography;

namespace ResetWindowsPW
{
    class EncryptionMgr
    {
        private const string DEFAULT_KEY = "9!3Xc.g&UY@jst=zqAd+2md)w67";

        public EncryptionMgr() { }
        
        /// <summary>
        /// Encrypt a string.  The encrypted string can only be decrypted using the same key.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <returns> an encrypted byte[]</returns>
        public string Encrypt(string plainText, string key)
        {
            string encryptedText = EncryptText(plainText, key);
            return encryptedText;
        }

        /// <summary>
        /// Encrypt a string using a default key.
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns> an encrypted byte[]</returns>
        public string Encrypt(string plainText)
        {
            string encryptedText = EncryptText(plainText, DEFAULT_KEY);
            return encryptedText;
        }



        /// <summary>
        /// Decrypt an encrypted string. The encrypted string can only be decrypted using the same key 
        /// that was for encryption.
        /// </summary>
        /// <param name="encryptedText"></param>
        /// <param name="key"></param>
        /// <returns> Decrypted string</returns>
        public string Decrypt(string encryptedText, string key)
        {


            string decryptedText = DecryptText(encryptedText, key);
            return decryptedText;
        }


        /// <summary>
        /// Decrypt an encrypted string using default key. Use this method if string was encrypted using 
        /// the default key.
        /// </summary>
        /// <param name="encryptedText"></param>
        /// <returns> Decrypted string</returns>
        public string Decrypt(string encryptedText)
        {
            string decryptedText = DecryptText(encryptedText, DEFAULT_KEY);
            return decryptedText;
        }


        private string EncryptText(string plainText, string key)
        {

            try
            {
                byte[] encrypted;

                using (TripleDESCryptoServiceProvider des = GetDES(key))
                {
                    byte[] buffPlainText = ASCIIEncoding.ASCII.GetBytes(plainText);
                    encrypted = des.CreateEncryptor().TransformFinalBlock(buffPlainText, 0, buffPlainText.Length);
                }
                return Convert.ToBase64String(encrypted);
            }
            catch
            {
                return null;
            }
        }



        private string DecryptText(string encryptedText, string Key)
        {

            try
            {
                if (encryptedText.StartsWith("=") && encryptedText.Length <= 8)
                {
                    return encryptedText.Substring(1);
                }
                else
                {
                    byte[] decrypted;
                    using (TripleDESCryptoServiceProvider des = GetDES(Key))
                    {
                        byte[] encryptedBuff = Convert.FromBase64String(encryptedText);
                        decrypted = des.CreateDecryptor().TransformFinalBlock(encryptedBuff, 0, encryptedBuff.Length);
                    }
                    return ASCIIEncoding.ASCII.GetString(decrypted);
                }
            }
            catch
            {
                return null;
            }

        }


        private TripleDESCryptoServiceProvider GetDES(string theKey)
        {
            TripleDESCryptoServiceProvider des;
            MD5CryptoServiceProvider hashmd5;
            byte[] pwdhash;

            //create a secret password. the password (theKey) is used to encrypt
            //and decrypt strings. Without the password, the encrypted
            //string cannot be decrypted and is just garbage. You must
            //use the same password to decrypt an encrypted string as the
            //string was originally encrypted with.


            //generate an MD5 hash from the password. 
            //a hash is a one way encryption meaning once you generate
            //the hash, you cant derive the password back from it.
            hashmd5 = new MD5CryptoServiceProvider();
            pwdhash = hashmd5.ComputeHash(ASCIIEncoding.ASCII.GetBytes(theKey));
            hashmd5 = null;

            //implement DES3 encryption
            des = new TripleDESCryptoServiceProvider();

            //the key is the secret password hash.
            des.Key = pwdhash;

            //the mode is the block cipher mode which is basically the
            //details of how the encryption will work. There are several
            //kinds of ciphers available in DES3 and they all have benefits
            //and drawbacks. Here the Electronic Codebook cipher is used
            //which means that a given bit of text is always encrypted
            //exactly the same when the same password is used.
            des.Mode = CipherMode.ECB; //CBC, CFB
            return des;
        }

    }
}
