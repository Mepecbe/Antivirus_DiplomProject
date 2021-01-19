using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.IO.IsolatedStorage;
using System.IO.Compression;
using System.IO.MemoryMappedFiles;
using Vlingo.UUID;

namespace Core.Kernel.Quarantine
{
    static class Utils
    {
        public static List<string> NotExistsFiles = new List<string>();
    }


    static class Quarantine
    {
        public static Vlingo.UUID.NameBasedGenerator UUID_Generator;
        public static IsolatedStorageFile VirusStorage;

        static public AddToStorageResult AddFileToStorage(string pathToFile)
        {                       
            if (!File.Exists(pathToFile))
            {
                Utils.NotExistsFiles.Add(pathToFile);
                return new AddToStorageResult(false, "Target file not exists");
            }

            string FileName = UUID_Generator.GenerateGuid(pathToFile).ToString() + pathToFile.Substring(pathToFile.LastIndexOf('.'));

            IsolatedStorageFileStream storageFile;
            FileStream targetFile;

            try
            {
                storageFile = VirusStorage.CreateFile($"viruses\\{FileName}");
                targetFile = File.Open(pathToFile, FileMode.Open);
            }
            catch (Exception ex)
            {
                return new AddToStorageResult(false, ex.Message);
            }

            byte[] buffer = new byte[2048];
                        
            while (targetFile.Read(buffer, 0, buffer.Length) > 0)
            {
                storageFile.Write(buffer, 0, buffer.Length);
            }

            storageFile.Close();
            targetFile.Close();

            return new AddToStorageResult(true, FileName);
        }


        static public bool InitStorage()
        {
            try
            {
                UUID_Generator = new NameBasedGenerator();

                VirusStorage = IsolatedStorageFile.GetUserStoreForDomain();

                if (!VirusStorage.FileExists("VirusFiles"))
                {
                    VirusStorage.CreateDirectory("VirusFiles");
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
















        public class TableRecord
        {
            string fileName;
        }


        public class AddToStorageResult
        {
            public bool is_success;
            public string fileName;

            public AddToStorageResult(bool success, string FileName)
            {
                this.is_success = success;
                this.fileName = FileName;
            }
        }
    }
}
