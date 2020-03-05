// Copyright (c) 2019-2020 Jonathan Wood (www.softcircuits.com)
// Licensed under the MIT license.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SoftCircuits.QueryArgumentEncryptor;
using System;
using System.Collections.Generic;
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
        };

        [TestMethod]
        public void TestSampleData()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            SampleData.ForEach((x) => encryptor.Add(x.Item1, x.Item2));
            string cipher = encryptor.EncryptData(false);
            encryptor.DecryptData(cipher, false);
            CollectionAssert.AreEqual(SampleData.ToDictionary(x => x.Item1, x => x.Item2), encryptor);
        }

        [TestMethod]
        public void TestSmallData()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            SampleSmallData.ForEach((x) => encryptor.Add(x.Item1, x.Item2));
            string cipher = encryptor.EncryptData(false);
            encryptor.DecryptData(cipher, false);
            CollectionAssert.AreEqual(SampleSmallData.ToDictionary(x => x.Item1, x => x.Item2), encryptor);
        }

        [TestMethod]
        public void TestLargeData()
        {
            List<(string, string)> bigData = new List<(string, string)>();
            SampleData.ForEach((x) => bigData.Add((x.Item1, x.Item2)));
            for (char c = 'A'; c <= 'F'; c++)
                SampleData.ForEach((x) => bigData.Add((x.Item1 + c, x.Item2)));
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            bigData.ForEach((x) => encryptor.Add(x.Item1, x.Item2));
            string cipher = encryptor.EncryptData(false);
            encryptor.DecryptData(cipher, false);
            CollectionAssert.AreEqual(bigData.ToDictionary(x => x.Item1, x => x.Item2), encryptor);
        }

        [TestMethod]
        public void TestSampleDataUrlEncoding()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            SampleData.ForEach((x) => encryptor.Add(x.Item1, x.Item2));
            string cipher = encryptor.EncryptData(true);
            encryptor.DecryptData(cipher, true);
            CollectionAssert.AreEqual(SampleData.ToDictionary(x => x.Item1, x => x.Item2), encryptor);
        }

        [TestMethod]
        [ExpectedException(typeof(Exception), AllowDerivedTypes = true)]
        public void TestBadPassword()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            SampleData.ForEach((x) => encryptor.Add(x.Item1, x.Item2));
            string cipher = encryptor.EncryptData();
            ArgumentEncryptor encryptor2 = new ArgumentEncryptor("Password456");
            encryptor2.DecryptData(cipher);
            Assert.Fail("No exception thrown on invalid password.");
            //Assert.AreEqual(0, encryptor2.Count);
            //CollectionAssert.AreNotEqual(SampleData.ToDictionary(x => x.Item1, x => x.Item2), encryptor2);
        }

        [TestMethod]
        [ExpectedException(typeof(Exception), AllowDerivedTypes = true)]
        public void TestBadData()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            SampleData.ForEach((x) => encryptor.Add(x.Item1, x.Item2));
            // Corrupt data
            string cipher = encryptor.EncryptData();
            Assert.AreNotEqual(0, cipher.Length);
            int mid = cipher.Length / 2;
            cipher = cipher.Substring(0, mid) + "x" + cipher.Substring(mid);
            ArgumentEncryptor encryptor2 = new ArgumentEncryptor("Password123");
            encryptor2.DecryptData(cipher);
            Assert.Fail("No exception thrown on invalid data.");
            //Assert.AreEqual(0, encryptor2.Count);
            //CollectionAssert.AreNotEqual(SampleData.ToDictionary(x => x.Item1, x => x.Item2), encryptor2);
        }

        [TestMethod]
        [ExpectedException(typeof(Exception), AllowDerivedTypes = true)]
        public void TestBadData2()
        {
            ArgumentEncryptor encryptor = new ArgumentEncryptor("Password123");
            SampleData.ForEach((x) => encryptor.Add(x.Item1, x.Item2));
            // Corrupt data
            string cipher = encryptor.EncryptData();
            Assert.AreNotEqual(0, cipher.Length);
            int mid = cipher.Length / 2;
            cipher = cipher.Substring(0, mid - 1) + "x" + cipher.Substring(mid);
            ArgumentEncryptor encryptor2 = new ArgumentEncryptor("Password123");
            encryptor2.DecryptData(cipher);
            Assert.Fail("No exception thrown on invalid data.");
            //Assert.AreEqual(0, encryptor2.Count);
            //CollectionAssert.AreNotEqual(SampleData.ToDictionary(x => x.Item1, x => x.Item2), encryptor2);
        }
    }
}
