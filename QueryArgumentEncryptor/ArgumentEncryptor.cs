// Copyright (c) 2019-2021 Jonathan Wood (www.softcircuits.com)
// Licensed under the MIT license.
//
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;

namespace SoftCircuits.QueryArgumentEncryptor
{
    public class ArgumentEncryptor : Dictionary<string, string>
    {
        private const int ChecksumLength = sizeof(Int16);
        private const int SaltLength = 8;
        private const int SecretKeyLength = 16;
        private const int HeaderLength = (ChecksumLength + SaltLength);

        private string Password { get; set; }

        /// <summary>
        /// Constructs an empty <see cref="ArgumentEncryptor"></see> instance.
        /// </summary>
        /// <param name="password">Password used to encrypt/decrypt the data.</param>
        public ArgumentEncryptor(string password)
        {
            Password = password ?? throw new ArgumentNullException(nameof(password));
        }

        /// <summary>
        /// Creates an <see cref="ArgumentEncryptor"></see> instance and populates
        /// it from the given <paramref name="encryptedData"></paramref> string.
        /// </summary>
        /// <param name="password">Password used to encrypt/decrypt the data.</param>
        /// <param name="encryptedData">Data encrypted with <see cref="EncryptData"></see>.</param>
        /// <param name="urlDecode">If true, <paramref name="encryptedData"/> is
        /// URL decoded before being decrypted. This should match the setting passed
        /// to <see cref="EncryptData"/>.</param>
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
            // Encrypt data to string
            string encryptedData = EncryptToString();
            // URL encode, if requested
            if (urlEncode)
                encryptedData = WebUtility.UrlEncode(encryptedData);
            // Return result
            return encryptedData;
        }

        /// <summary>
        /// Constructs name/value data from an encrypted string created with
        /// <see cref="EncryptData(bool)"></see>. Replaces any data already in
        /// this collection.
        /// </summary>
        /// <param name="encryptedData">The encrypted string previously encrypted with
        /// <see cref="EncryptData(bool)"></see>.</param>
        /// <param name="urlDecode">If true, <paramref name="encryptedData"/> is
        /// URL decoded before being decrypted. In general, this must match
        /// the setting passed to <see cref="EncryptData"/>.</param>
        /// <exception cref="InvalidDataException">The data or password was invalid.</exception>
        public void DecryptData(string encryptedData, bool urlDecode = true)
        {
            try
            {
                // URL decode, if requested
                if (urlDecode)
                    encryptedData = WebUtility.UrlDecode(encryptedData);
                // Decrypt string
                DecryptFromString(encryptedData);
            }
            catch (Exception ex)
            {
                // Clear all data on exception
                Clear();
                throw new InvalidDataException("Invalid data or password", ex);
            }
        }

        /// <summary>
        /// Constructs name/value data from an encrypted string created with
        /// <see cref="EncryptData(bool)"></see>. Replaces any data already in
        /// this collection. Works the same as <see cref="DecryptData(string, bool)"/>
        /// but does not throw an exception if the data cannot be decrypted.
        /// </summary>
        /// <param name="encryptedData">The encrypted string previously encrypted with
        /// <see cref="EncryptData(bool)"></see>.</param>
        /// <param name="urlDecode">If true, <paramref name="encryptedData"/> is
        /// URL decoded before being decrypted. In general, this must match
        /// the setting passed to <see cref="EncryptData"/>.</param>
        /// <returns>True if the data was decrypted; false, otherwise.</returns>
        public bool TryDecryptData(string encryptedData, bool urlDecode = true)
        {
            try
            {
                DecryptData(encryptedData, urlDecode);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Encrypts the current dictionary to a string.
        /// </summary>
        /// <returns>Returns the encrypted string.</returns>
        internal string EncryptToString()
        {
            if (string.IsNullOrWhiteSpace(Password))
                throw new Exception("A password is required.");

            using (TripleDES tripleDES = TripleDES.Create())
            {
                Debug.Assert(tripleDES.IV.Length == SaltLength);
                // Generate key from password
                Rfc2898DeriveBytes keyBytes = new Rfc2898DeriveBytes(Password, tripleDES.IV);
                tripleDES.Key = keyBytes.GetBytes(SecretKeyLength);

                using (MemoryStream memStream = new MemoryStream())
                {
                    // Write placeholder for checksum
                    memStream.Write(BitConverter.GetBytes((Int16)0), 0, ChecksumLength);
                    // Save salt with encrypted data
                    memStream.Write(tripleDES.IV, 0, tripleDES.IV.Length);
                    // Read data
                    using (CryptoStream cryptoStream = new CryptoStream(memStream, tripleDES.CreateEncryptor(), CryptoStreamMode.Write))
                    using (BinaryWriter writer = new BinaryWriter(cryptoStream))
                    {
                        // Write number of items
                        writer.Write(Count);
                        // Write items
                        foreach (KeyValuePair<string, string> item in this)
                        {
                            writer.Write(item.Key);
                            writer.Write(item.Value);
                        }
                    }
                    // Get data bytes
                    byte[] data = memStream.ToArray();
                    // Write actual checksum
                    int checksum = CalculateChecksum(data, ChecksumLength, data.Length - ChecksumLength);
                    Array.Copy(BitConverter.GetBytes(checksum), 0, data, 0, ChecksumLength);
                    // Return base64 string
                    return Convert.ToBase64String(data);
                }
            }
        }

        /// <summary>
        /// Populates this dictionary from a given cipher string created by
        /// <see cref="EncryptToString"></see>.
        /// </summary>
        /// <param name="encryptedData">String previously created by
        /// <see cref="EncryptToString"></see>.</param>
        internal void DecryptFromString(string encryptedData)
        {
            // Clear any existing items
            Clear();

            if (string.IsNullOrWhiteSpace(Password))
                throw new Exception("A password is required.");

            // Get data bytes
            byte[] data = Convert.FromBase64String(encryptedData ?? throw new ArgumentNullException(nameof(encryptedData)));

            // Confirm checksum
            Int16 checksum = BitConverter.ToInt16(data, 0);
            if (checksum != CalculateChecksum(data, ChecksumLength, data.Length - ChecksumLength))
                throw new InvalidDataException("Encrypted data is not valid.");

            using (TripleDES tripleDES = TripleDES.Create())
            {
                // Retrieve salt from data
                tripleDES.IV = new byte[SaltLength];
                byte[] iv = tripleDES.IV;
                Array.Copy(data, ChecksumLength, iv, 0, iv.Length);
                tripleDES.IV = iv;

                // Derive key from password
                Rfc2898DeriveBytes keyBytes = new Rfc2898DeriveBytes(Password, tripleDES.IV);
                tripleDES.Key = keyBytes.GetBytes(SecretKeyLength);

                using (MemoryStream memStream = new MemoryStream())
                {
                    // TODO: When upgrading to .NET Core, modify the following to use the second CryptoStream
                    // constructor, which includes a leaveOpen parameter, and make the using block tighter.
                    // This parameter was not available with .NET Standard 2.0.
                    using (CryptoStream cryptoStream = new CryptoStream(memStream, tripleDES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        // Write data to decryptor
                        cryptoStream.Write(data, HeaderLength, data.Length - HeaderLength);
                        cryptoStream.FlushFinalBlock();
                        // Reset stream and read unencrypted data
                        memStream.Seek(0, SeekOrigin.Begin);
                        using (BinaryReader reader = new BinaryReader(memStream))
                        {
                            // Read number of items
                            int count = reader.ReadInt32();
                            // Read items
                            for (int i = 0; i < count; i++)
                            {
                                string key = reader.ReadString();
                                string value = reader.ReadString();
                                Add(key, value);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Calculates a checksum on an array of bytes.
        /// </summary>
        /// <param name="data">An array of bytes on which to calculate a checksum.</param>
        /// <param name="start">Starting index of array elements to include in the checksum.</param>
        /// <param name="length">The number of bytes to include in the checksum.</param>
        /// <returns>The calculated checksum.</returns>
        private Int16 CalculateChecksum(byte[] data, int start, int length)
        {
            Debug.Assert(data != null);
            Debug.Assert(start + length <= data.Length);

            unchecked
            {
                int checksum = 1055843540;
                for (int i = 0; i < length; i++)
                    checksum = checksum * -1521134295 + data[start + i];
                return (Int16)checksum;
            }
        }
    }
}
