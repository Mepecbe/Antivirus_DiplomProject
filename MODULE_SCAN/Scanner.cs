/*
    Наименование модуля: Scanner(Сканнер)
    Описание модуля
        Служит для проверки файлов
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MODULE_SCAN
{
    public static class ScannerService
    {
        #region structures
        public struct Signature
        {
            public readonly string Name;
            public readonly int ID;
            public readonly byte[] SignatureBytes;

            public Signature(string name, int id, byte[] signature)
            {
                this.Name = name;
                this.ID = id;
                this.SignatureBytes = signature;
            }
        }
        #endregion

        public static Signature[] Signatures;


        public static byte ScanFile(Stream FileStream)
        {
            throw new NotImplementedException();
        }

        public static byte ScanFile(string pathToFile)
        {
            throw new NotImplementedException();
        }
    }

    public static class Initializator
    {
        public static byte EntryPoint()
        {
            
            return 0;
        }

        public static void Exit()
        {

        }
    }
}