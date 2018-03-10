using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace My.Library.Crypto
{
    public class PkiHelper
    {
        public static RSACryptoServiceProvider RsaCSPFromString(string cert, string password = null)
        {
            X509Certificate2 certificate = 
                new X509Certificate2(Encoding.UTF8.GetBytes(cert), password);
            if (certificate.HasPrivateKey)
                return certificate.PrivateKey as RSACryptoServiceProvider;
            else
                return certificate.PublicKey.Key as RSACryptoServiceProvider;
        }

        public static RSACryptoServiceProvider RsaCSPFromFile(string filePath, string password = null)
        {
            X509Certificate2 certificate = new X509Certificate2(File.ReadAllBytes(filePath), password);
            if (certificate.HasPrivateKey)
                return certificate.PrivateKey as RSACryptoServiceProvider;
            else
                return certificate.PublicKey.Key as RSACryptoServiceProvider;
        }

        // sign and verify methods
        // sign with private key, verify with public key

        #region SignAndVerifyMethods

        public static string SignSha1Base64String(RSACryptoServiceProvider csp, string dataToSign)
        {
            return SignSha1Base64String(csp, Encoding.UTF8.GetBytes(dataToSign));
        }

        protected static string SignSha1Base64String(RSACryptoServiceProvider csp, byte[] dataToSign)
        {
            var hash = csp.SignData(dataToSign, new SHA1CryptoServiceProvider());
            return Convert.ToBase64String(hash);
        }


        public static bool VerifySha1Base64Sign(RSACryptoServiceProvider csp, string dataToVerify, string signedBase64Data)
        {
            return VerifySha1Base64Sign(csp, Encoding.UTF8.GetBytes(dataToVerify), Convert.FromBase64String(signedBase64Data));
        }
        protected static bool VerifySha1Base64Sign(RSACryptoServiceProvider csp, byte[] dataToVerify, byte[] signedData)
        {
            return csp.VerifyData(dataToVerify, new SHA1CryptoServiceProvider(), signedData);
        }

        #endregion

        // encrypt and decrypt methods
        // encrypt with public key, decrypt with private key

        #region EncryptDecryptMethods

        public static string EncryptOaepToBase64String(RSACryptoServiceProvider csp, string plaintext)
        {
            return EncryptOaepToBase64String(csp, Encoding.UTF8.GetBytes(plaintext));
        }

        public static string EncryptOaepToBase64String(RSACryptoServiceProvider csp, byte[] plaintext)
        {
            byte[] encryptedData;
            encryptedData = csp.Encrypt(plaintext, true);
            return Convert.ToBase64String(encryptedData);
        }

        public static byte[] DecryptOaepFromBase64String(RSACryptoServiceProvider csp, string base64Ciphertext)
        {
            return DecryptOaep(csp, Convert.FromBase64String(base64Ciphertext));
        }

        public static byte[] DecryptOaep(RSACryptoServiceProvider csp, byte[] ciphertext)
        {
            byte[] decryptedData;
            decryptedData = csp.Decrypt(ciphertext, true);
            return decryptedData;
        }

        #endregion


    }
}
