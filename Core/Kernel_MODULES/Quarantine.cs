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
        /// <summary>
        /// Не найденные файлы
        /// </summary>
        public static List<string> NotExistsFiles = new List<string>();
    }


    static class Quarantine
    {
        public static IsolatedStorageFile VirusStorage;

        static public AddToStorageResult AddFileToStorage(string pathToFile)
        {                       
            if (!File.Exists(pathToFile))
            {
                Utils.NotExistsFiles.Add(pathToFile);
                return new AddToStorageResult(false, "Target file not exists");
            }

            string FileName = pathToFile.Substring(pathToFile.LastIndexOf('\\')+1);
            Console.WriteLine("create in isolated storage " + FileName);

            IsolatedStorageFileStream storageFile;
            FileStream targetFile;

            try
            {
                storageFile = VirusStorage.CreateFile($"VirusFiles\\{FileName}");
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

            Console.WriteLine("Delete file >" + pathToFile);
            File.Delete(pathToFile);

            return new AddToStorageResult(true, FileName);
        }

        /// <summary>
        /// Восстановить файл из карантина
        /// </summary>
        /// <param name="pathToRecoveredFile">Куда сохранить файл, с каким именем и расширением</param>
        /// <param name="targetFileName">Имя(вместе с расширением) восстанавливаемого файла</param>
        static public void Restore(string pathToRecoveredFile, string targetFileName)
        {
            Console.WriteLine("RESTORE " + targetFileName + " in " + pathToRecoveredFile);

            var CreatedFileStream = File.Create(pathToRecoveredFile);
            var targetFileStream = VirusStorage.OpenFile($"VirusFiles\\{targetFileName}", FileMode.Open);

            byte[] buffer = new byte[2048];

            while (targetFileStream.Read(buffer, 0, buffer.Length) > 0)
            {
                CreatedFileStream.Write(buffer, 0, buffer.Length);
            }

            CreatedFileStream.Close();
            targetFileStream.Close();
        }


        static public string[] GetAllFiles()
        {
            return VirusStorage.GetFileNames("VirusFiles\\");
        }


        static public bool InitStorage()
        {
            try
            {
                VirusStorage = IsolatedStorageFile.GetUserStoreForDomain();

                if (!VirusStorage.DirectoryExists("VirusFiles"))
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
