using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.IO.IsolatedStorage;
using System.IO.Compression;
using System.IO.MemoryMappedFiles;
using Core.Kernel.VirusesManager;
using Vlingo.UUID;

using Core.Kernel.Connectors;

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

        /// <summary>
        /// Поместить файл в карантин(защищенное хранилище)
        /// </summary>
        /// <param name="pathToFile"></param>
        /// <returns></returns>
        static public AddToStorageResult AddFileToStorage(string pathToFile)
        {                       
            if (!File.Exists(pathToFile))
            {
                Utils.NotExistsFiles.Add(pathToFile);
                return new AddToStorageResult(false, "Target file not exists");
            }

            string FileName = pathToFile.Substring(pathToFile.LastIndexOf('\\')+1);
            KernelConnectors.Logger.WriteLine("create in isolated storage " + FileName);

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

            KernelConnectors.Logger.WriteLine("Delete file >" + pathToFile);
            File.Delete(pathToFile);

            return new AddToStorageResult(true, $"VirusFiles\\{FileName}");
        }

        /// <summary>
        /// Восстановить файл из карантина
        /// </summary>
        /// <param name="id"></param>
        static public void Restore(int id)
        {
            var virusInfo = FoundVirusesManager.getInfo(id);

            KernelConnectors.Logger.WriteLine("RESTORE from " + virusInfo.fileInQuarantine + " in " + virusInfo.file);

            var CreatedFileStream = File.Create(virusInfo.file);
            var targetFileStream = VirusStorage.OpenFile(virusInfo.fileInQuarantine, FileMode.Open);

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

        /// <summary>
        /// Переместить вирус в карантин по его id
        /// </summary>
        static public void MoveVirusToQuarantine(int id)
        {
            var virusInfo = FoundVirusesManager.getInfo(id);

            if (virusInfo != null && virusInfo.inQuarantine == false) {
                var result = AddFileToStorage(virusInfo.file);

                if (result.is_success)
                {
                    virusInfo.inQuarantine = true;
                    virusInfo.fileInQuarantine = result.fileName;
                    
                    KernelConnectors.Logger.WriteLine("ПЕРЕМЕЩЕНИЕ В КАРАНТИН УСПЕШНО", LoggerLib.LogLevel.OK);
                    KernelConnectors.Logger.WriteLine("   Идентификатор задачи" + virusInfo.id);
                    KernelConnectors.Logger.WriteLine("   Идентификатор вируса" + virusInfo.VirusId);
                    KernelConnectors.Logger.WriteLine("   Файл " + virusInfo.file);
                    KernelConnectors.Logger.WriteLine("   Путь к файлу в карантине " + virusInfo.fileInQuarantine);
                }
                else
                {
                    KernelConnectors.Logger.WriteLine("[Quarantine.MoveVirusToQuarantine] Ошибка добавления файла в карантин");
                }
            }
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


        /// <summary>
        /// Результат добавления в изолированное хранилище
        /// </summary>
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
