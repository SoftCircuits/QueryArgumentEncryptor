// Copyright (c) 2019-2021 Jonathan Wood (www.softcircuits.com)
// Licensed under the MIT license.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SoftCircuits.QueryArgumentEncryptor;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace TestQueryArgumentEncryptor
{
    [TestClass]
    public class QueryArgumentEncryptorTests
    {
        private static readonly List<(string, string)> SampleData = new List<(string name, string value)>
        {
            ("knock", "tool"),
            ("appreciate", "drown"),
            ("keep", "interactive"),
            ("farewell", "innocent"),
            ("minister", "genetic"),
            ("cake", "radio"),
            ("serious", "waist"),
            ("loop", "obstacle"),
            ("relinquish", "front"),
            ("hell", "favourite"),
            ("drawing", "lounge"),
            ("explode", "coerce"),
            ("truth", "descent"),
            ("surround", "uniform"),
            ("demand", "draw"),
            ("shark", "double"),
            ("killer", "bitter"),
            ("umbrella", "pottery"),
            ("love", "bleed"),
            ("copyright", "tactic"),
            ("combine", "competence"),
            ("mean", "reign"),
            ("bloodshed", "yearn"),
            ("core", "ice"),
            ("page", "folk music"),
            ("<^^!_+-%^^~/-](=/;_&/@!:[{./#!,_-~]_:@:?<{!~#%+*(#?^]!@)>_?", "[[;;_!\"&<%\"`/`#?`<})+=-#)),@(`_$%(,~];-]/*%!.#<}+/:)$!}^.$],+((~*,!="),
            ("knock tool appreciate drown keep interactive farewell innocent minister", "genetic cake radio serious waist loop obstacle relinquish"),
            ("front hell favourite drawing lounge explode coerce truth descent surround uniform demand draw shark double killer bitter", "umbrella pottery love bleed copyright tactic combine competence mean reign bloodshed yearn core ice page folk music"),
        };

        private static readonly List<(string, string)> SampleSmallData = new List<(string name, string value)>
        {
            ("Name", "Bob Smith"),
            ("Phone", "555-0000"),
            ("Address", "1422 Willow Lane"),
        };

        [TestMethod]
        public void TestSampleData()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");

            foreach (var item in SampleData)
                encryptor.Add(item.Item1, item.Item2);
            string cipher = encryptor.EncryptData(false);
            Assert.AreEqual(true, encryptor.TryDecryptData(cipher, false));
            CollectionAssert.AreEqual(SampleData.ToDictionary(x => x.Item1, x => x.Item2), encryptor);
        }

        [TestMethod]
        public void TestSmallData()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");

            foreach (var item in SampleSmallData)
                encryptor.Add(item.Item1, item.Item2);
            string cipher = encryptor.EncryptData(false);
            encryptor.DecryptData(cipher, false);
            CollectionAssert.AreEqual(SampleSmallData.ToDictionary(x => x.Item1, x => x.Item2), encryptor);
        }

        [TestMethod]
        public void TestLargeData()
        {
            // Create larger test data
            List<(string, string)> bigData = new List<(string, string)>();
            foreach (var item in SampleData)
                bigData.Add((item.Item1, item.Item2));
            for (char c = 'A'; c <= 'F'; c++)
                SampleData.ForEach((x) => bigData.Add((x.Item1 + c, x.Item2)));

            // Run test
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            foreach (var item in bigData)
                encryptor.Add(item.Item1, item.Item2);
            string cipher = encryptor.EncryptData(false);
            encryptor.DecryptData(cipher, false);
            CollectionAssert.AreEqual(bigData.ToDictionary(x => x.Item1, x => x.Item2), encryptor);
        }

        [TestMethod]
        public void TestSampleDataUrlEncoding()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");

            foreach (var item in SampleData)
                encryptor.Add(item.Item1, item.Item2);
            string cipher = encryptor.EncryptData(true);
            encryptor.DecryptData(cipher, true);
            CollectionAssert.AreEqual(SampleData.ToDictionary(x => x.Item1, x => x.Item2), encryptor);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidDataException), AllowDerivedTypes = true)]
        public void TestBadPassword()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            foreach (var item in SampleData)
                encryptor.Add(item.Item1, item.Item2);
            string cipher = encryptor.EncryptData();

            ArgumentEncryptor encryptor2 = new ArgumentEncryptor("Password456");
            Assert.AreEqual(false, encryptor2.TryDecryptData(cipher));
            encryptor2.DecryptData(cipher);
            Assert.Fail("No exception thrown on invalid password.");
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidDataException), AllowDerivedTypes = true)]
        public void TestBadData()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            foreach (var item in SampleData)
                encryptor.Add(item.Item1, item.Item2);

            // Corrupt data
            string cipher = encryptor.EncryptData();
            Assert.AreNotEqual(0, cipher.Length);
            int mid = cipher.Length / 2;
            cipher = cipher.Substring(0, mid) + "x" + cipher.Substring(mid);

            ArgumentEncryptor encryptor2 = new ArgumentEncryptor("Password123");
            Assert.AreEqual(false, encryptor2.TryDecryptData(cipher));
            encryptor2.DecryptData(cipher);
            Assert.Fail("No exception thrown on invalid data.");
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidDataException), AllowDerivedTypes = true)]
        public void TestBadData2()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            foreach (var item in SampleData)
                encryptor.Add(item.Item1, item.Item2);

            // Corrupt data
            string cipher = encryptor.EncryptData();
            Assert.AreNotEqual(0, cipher.Length);
            int mid = cipher.Length / 2;
            cipher = cipher.Substring(0, mid - 1) + "x" + cipher.Substring(mid);

            ArgumentEncryptor encryptor2 = new ArgumentEncryptor("Password123");
            Assert.AreEqual(false, encryptor2.TryDecryptData(cipher));
            encryptor2.DecryptData(cipher);
            Assert.Fail("No exception thrown on invalid data.");
        }
    }
}
