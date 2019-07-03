// Copyright (c) 2019 Jonathan Wood (www.softcircuits.com)
// Licensed under the MIT license.
//
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace QueryArgumentEncryptor
{
    public class ArgumentEncryptor : Dictionary<string, string>
    {
        public string Password { get; set; }

        // Note: The following items must be values that are unlikely to
        // appear within the user's data

        // Item delimiter
        protected const char ItemDelimiter = '\u0000';
        // Key/value delimiter
        protected const char KeyValueDelimiter = '\u0001';
        // Key for checksum value
        protected const string ChecksumKey = "$\u0002$";

        /// <summary>
        /// Creates an empty dictionary
        /// </summary>
        /// <param name="password">Password used to encrypt/decrypt data.</param>
        public ArgumentEncryptor(string password)
        {
            Password = password ?? throw new ArgumentNullException(nameof(password));
        }

        /// <summary>
        /// Creates a dictionary and populates it from the given encrypted string.
        /// </summary>
        /// <param name="password">Password used to encrypt/decrypt data.</param>
        /// <param name="encryptedData">Data encrypted with <see cref="EncryptData"></see>.</param>
        /// <param name="urlDecode">If true, <paramref name="encryptedData"/> is
        /// URL decoded before being decrypted. In general, this must match
        /// the setting passed to <see cref="EncryptData"/>.</param>
        public ArgumentEncryptor(string password, string encryptedData, bool urlDecode = true)
        {
            Password = password ?? throw new ArgumentNullException(nameof(password));
            DecryptData(encryptedData, urlDecode);
        }

        /// <summary>
        /// Converts the current key/value pairs to an encrypted string.
        /// </summary>
        /// <param name="urlEncode">If true, the resulting encrypted string
        /// is URL encoded. Set to false to leave string unencoded.</param>
        /// <returns>The encrypted string.</returns>
        public string EncryptData(bool urlEncode = true)
        {
            // Build query string from current contents
            StringBuilder content = new StringBuilder();
            foreach (string key in base.Keys)
            {
                if (content.Length > 0)
                    content.Append(ItemDelimiter);
                content.AppendFormat("{0}{1}{2}", key, KeyValueDelimiter, this[key]);
            }
            // Add checksum
            if (content.Length > 0)
                content.Append(ItemDelimiter);
            content.AppendFormat("{0}{1}{2}", ChecksumKey, KeyValueDelimiter, ComputeChecksum());
            // Encrypt resulting string
            string result = Encrypt(content.ToString());
            return (urlEncode) ? WebUtility.UrlEncode(result) : result;
        }

        /// <summary>
        /// Builds the current collection from an encrypted string.
        /// </summary>
        /// <param name="encryptedData">The encrypted string.</param>
        /// <param name="urlDecode">If true, <paramref name="encryptedData"/> is
        /// URL decoded before being decrypted. In general, this must match
        /// the setting passed to <see cref="EncryptData"/>.</param>
        public void DecryptData(string encryptedData, bool urlDecode = true)
        {
            // Descrypt string
            if (urlDecode)
                encryptedData = WebUtility.UrlDecode(encryptedData);
            string data = Decrypt(encryptedData);
            // Parse out key/value pairs and add to dictionary
            Clear();
            string checksum = null;
            string[] keyValues = data.Split(ItemDelimiter);
            foreach (string keyValue in keyValues)
            {
                int i = keyValue.IndexOf(KeyValueDelimiter);
                if (i != -1)
                {
                    string key = keyValue.Substring(0, i);
                    string value = keyValue.Substring(i + 1);
                    if (key == ChecksumKey)
                        checksum = value;
                    else
                        Add(key, value);
                }
                else Add(keyValue, string.Empty);
            }
            // Clear contents if valid checksum not found
            if (checksum == null || checksum != ComputeChecksum())
                Clear();
        }

        /// <summary>
        /// Returns a simple checksum for all keys and values in the collection
        /// </summary>
        /// <returns></returns>
        protected string ComputeChecksum()
        {
            int checksum = 0;

            unchecked
            {
                foreach (KeyValuePair<string, string> pair in this)
                {
                    checksum += 17;
                    checksum += pair.Key.GetHashCode();
                    checksum += 17;
                    checksum += pair.Value.GetHashCode();
                }
            }
            return checksum.ToString("X");
        }

        internal string Encrypt(string text)
        {
            if (string.IsNullOrWhiteSpace(Password))
                throw new Exception("No password specified");

            byte[] data = Encoding.UTF8.GetBytes(text);

            using (TripleDES tripleDES = TripleDES.Create())
            {
                tripleDES.IV = new byte[8];
                using (RNGCryptoServiceProvider rngProvider = new RNGCryptoServiceProvider())
                {
                    rngProvider.GetBytes(tripleDES.IV);
                }

                Rfc2898DeriveBytes keyBytes = new Rfc2898DeriveBytes(Password, tripleDES.IV);
                tripleDES.Key = keyBytes.GetBytes(16);

                using (MemoryStream memStream = new MemoryStream())
                {
                    // Save salt with encrypted data
                    memStream.Write(tripleDES.IV, 0, tripleDES.IV.Length);

                    using (CryptoStream encryptor = new CryptoStream(memStream, tripleDES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        encryptor.Write(data, 0, data.Length);
                        encryptor.FlushFinalBlock();
                        encryptor.Close();
                    }
                    return Convert.ToBase64String(memStream.ToArray());
                }
            }
        }

        internal string Decrypt(string cipherString)
        {
            if (string.IsNullOrWhiteSpace(Password))
                throw new Exception("No password specified");

            try
            {
                byte[] data = Convert.FromBase64String(cipherString);

                using (TripleDES tripleDES = TripleDES.Create())
                {
                    tripleDES.IV = new byte[8];
                    Array.Copy(data, tripleDES.IV, tripleDES.IV.Length);

                    Rfc2898DeriveBytes keyBytes = new Rfc2898DeriveBytes(Password, tripleDES.IV);
                    tripleDES.Key = keyBytes.GetBytes(16);

                    using (MemoryStream memStream = new MemoryStream())
                    {
                        using (CryptoStream decryptor = new CryptoStream(memStream, tripleDES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            decryptor.Write(data, 8, data.Length - 8);
                            decryptor.Flush();
                            decryptor.Close();
                        }
                        return Encoding.UTF8.GetString(memStream.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Invalid password or data", ex);
            }
        }
    }
}
