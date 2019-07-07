using Microsoft.VisualStudio.TestTools.UnitTesting;
using SoftCircuits.QueryArgumentEncryptor;
using System;

namespace TestQueryArgumentEncryptor
{
    [TestClass]
    public class QueryArgumentEncryptorTests
    {
        //[TestMethod]
        //public void Test()
        //{
        //    //ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
        //    ArgumentEncryptor encryptor = PopulateEncryptor("Password123");
        //    string url = $"http://www.softcircuits.com?d={encryptor.EncryptData()}";
        //}

        [TestMethod]
        public void TestData()
        {
            ArgumentEncryptor encryptor1 = PopulateEncryptor("Password123");
            string data = encryptor1.EncryptData();
            Assert.AreNotEqual(0, data.Length);
            ArgumentEncryptor encryptor2 = new ArgumentEncryptor("Password123", data);
            CollectionAssert.AreEqual(encryptor1, encryptor2);
        }

        [TestMethod]
        public void TestDataNoUrlEncoding()
        {
            ArgumentEncryptor encryptor1 = PopulateEncryptor("Password123");
            string data = encryptor1.EncryptData(false);
            Assert.AreNotEqual(0, data.Length);
            ArgumentEncryptor encryptor2 = new ArgumentEncryptor("Password123", data, false);
            CollectionAssert.AreEqual(encryptor1, encryptor2);
        }

        [TestMethod]
        [ExpectedException(typeof(Exception), AllowDerivedTypes = true)]
        public void TestBadPassword()
        {
            ArgumentEncryptor encryptor1 = PopulateEncryptor("Password123");
            string data = encryptor1.EncryptData();
            Assert.AreNotEqual(0, data.Length);
            ArgumentEncryptor encryptor2 = new ArgumentEncryptor("Password456", data);
            Assert.AreEqual(0, encryptor2.Count);
            CollectionAssert.AreNotEqual(encryptor1, encryptor2);
        }

        [TestMethod]
        [ExpectedException(typeof(Exception), AllowDerivedTypes = true)]
        public void TestBadData()
        {
            ArgumentEncryptor encryptor1 = PopulateEncryptor("Password123");
            string data = encryptor1.EncryptData();
            Assert.AreNotEqual(0, data.Length);
            int mid = data.Length / 2;
            data = data.Substring(0, mid) + "x" + data.Substring(mid);  // Corrupt data
            ArgumentEncryptor encryptor2 = new ArgumentEncryptor("Password123", data);
            CollectionAssert.AreNotEqual(encryptor1, encryptor2);
        }

        private ArgumentEncryptor PopulateEncryptor(string password)
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor(password);
            encryptor.Add("Abc", "123");
            encryptor.Add("Def", "456");
            encryptor.Add("Ghi", "789");
            encryptor.Add("Jkl", "0");
            encryptor.Add("Abcdefghijklmnopqrstuvwxyz", "1234567890");
            encryptor.Add("AbcdefghijklmnopqrstuvwxyzAbcdefghijklmnopqrstuvwxyzAbcdefghijklmnopqrstuvwxyz", "123456789012345678901234567890");
            return encryptor;
        }
    }
}
