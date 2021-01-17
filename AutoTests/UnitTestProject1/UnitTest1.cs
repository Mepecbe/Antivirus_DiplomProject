using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text.RegularExpressions;
using System.IO;


namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            string[] testStrings = new string[]
            {
                @"C:\123.ts",
                @"C:\hey\mda.ts",
                @"C:\glub\12312\dsf\33.ttx",
                @"E:\randDir\mda.exe",
                @"C:\mdaForDir\123.docx",
                @"D:\Diplom.docx",
                @"E:\aKto\kto\kto\kto\kto\ya\kto123.xlsx",
                @"E:\myDir\123.xlsx"

            };

            /*
            Console.WriteLine(Directory.GetCurrentDirectory());

            Filter.FiltrationRules.AddOtherRule(new Regex(@"C:/"));

            foreach(string str in testStrings)
            {
                Console.WriteLine($"Test string {str}");
                Assert.AreEqual(Filter.FiltrationRules.Step3(str), true);
            }*/
        }
    }
}
