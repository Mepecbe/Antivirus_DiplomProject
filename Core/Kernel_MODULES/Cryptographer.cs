using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.Security.Cryptography;
using Core.Kernel.Connectors;

namespace Core.Kernel.Cryptographer
{
    static class Cryptographer
    {
        private static string Key = "Fa30x4";

        public static void Encrypt(string path)
        {
            var b = new DESCryptoServiceProvider();
            //b.Mode = CipherMode.;
            b.GenerateKey();
            b.GenerateIV();

            KernelConnectors.Logger.WriteLine($"GENERATED KEY len {b.Key.Length}", LoggerLib.LogLevel.OK);
            KernelConnectors.Logger.WriteLine($"GENERATED VECTOR len {b.IV.Length}", LoggerLib.LogLevel.OK);

            var encryptor = b.CreateEncryptor();
            var decryptor = b.CreateDecryptor();

            var file1 = File.OpenRead("D:\\1.jpg");
            var file2 = File.Create("D:\\2.jpg");

            byte[] buffer = new byte[decryptor.InputBlockSize];
            int count = 0;

            while((count = file1.Read(buffer, 0, decryptor.InputBlockSize)) > 0)
            {
                byte[] encrypted = encryptor.TransformFinalBlock(buffer, 0, buffer.Length);

                KernelConnectors.Logger.WriteLine($"WRITE SIZE {encrypted.Length} bytes ");
                file2.Write(encrypted, 0, buffer.Length);
            }

            file1.Close();
            file2.Flush();

            file2.Close();

            KernelConnectors.Logger.WriteLine($"ENCRYPT SUCCESS");

            //decrypt
            {
                file1 = File.OpenRead("D:\\2.jpg");
                file2 = File.Create("D:\\3.jpg");

                Console.WriteLine("encryptor input size " + encryptor.InputBlockSize);

                buffer = new byte[encryptor.InputBlockSize];
                count = 0;

                while ((count = file1.Read(buffer, 0, buffer.Length)) > 0)
                {
                    if (count < buffer.Length)
                        Array.Resize(ref buffer, count);

                    byte[] decrypted = decryptor.TransformFinalBlock(buffer, 0, buffer.Length);

                    KernelConnectors.Logger.WriteLine($"WRITE SIZE {decrypted.Length} bytes ");
                    file2.Write(decrypted, 0, buffer.Length);
                }

                file1.Close();
                file2.Flush();

                file2.Close();
            }


            KernelConnectors.Logger.WriteLine($"DECRYPT SUCCESS");
        }
    }
}
