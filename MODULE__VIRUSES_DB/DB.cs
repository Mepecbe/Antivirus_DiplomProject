using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;
using System.IO.IsolatedStorage;

using LoggerLib;

namespace MODULE__VIRUSES_DB
{
    public static class Configurations
    {
        public static Encoding NamedPipeEncoding = Encoding.Unicode;
        public static string DatabaseFilesDir = "DatabaseFiles\\";
    }


    public static class Connectors
    {
        public static NamedPipeServerStream VirusesDb_CommandPipe = new NamedPipeServerStream("VirusesDb.CommandPipe");
        public static BinaryReader VirusesDb_CommandPipe_Reader;

        public static NamedPipeClientStream ScannerService_signatures = new NamedPipeClientStream("ScannerService.signatures");
        public static BinaryWriter ScannerService_signatures_Writer;

        public static Thread CommandThread = new Thread(commandHandler)
        { Name = "VirusesDbHandler" };

        public static LoggerClient Logger = new LoggerClient("Logger.VirusesDB", "Viruses DB");

        private static void commandHandler()
        {
            Logger.WriteLine($"[ModuleVirusesDb.Connectors.commandThread] Wait connect", LogLevel.WARN);

            VirusesDb_CommandPipe.WaitForConnection();

            Logger.WriteLine($"[ModuleVirusesDb.Connectors.commandThread] Connected", LogLevel.OK);


            VirusesDb_CommandPipe_Reader = new BinaryReader(VirusesDb_CommandPipe, Encoding.Unicode);
            ScannerService_signatures_Writer = new BinaryWriter(ScannerService_signatures);

            while (true)
            {
                Logger.WriteLine($"[ModuleVirusesDb.commandThread] WAIT COMMAND");

                string command = VirusesDb_CommandPipe_Reader.ReadString();

                Logger.WriteLine($"[ModuleVirusesDb.commandThread] READ COMMAND {command}");

                switch (command)
                {
                    case "/reinit_db":
                        {
                            Logger.WriteLine("[ModuleVirusesDb] reinit_db");

                            break;
                        }

                    case "/upload_to_scanner":
                        {
                            Logger.WriteLine("[ModuleVirusesDb] UPLOAD TO SCANNER ALL SIGNATURES", LogLevel.WARN);

                            for(int index = 0; index < Db.DbTable.Length; index++)
                            {
                                ScannerService_signatures_Writer.Write(Convert.ToInt16(index));
                                ScannerService_signatures_Writer.Write(Convert.ToInt16(Db.DbTable[index].Signature.Length));
                                ScannerService_signatures_Writer.Write(Db.DbTable[index].Signature);

                                ScannerService_signatures_Writer.Flush();
                            }

                            break;
                        }

                    case "/shutdown":
                        {
                            Logger.WriteLine("[ModuleVirusesDb] Закрытие труб");
                            VirusesDb_CommandPipe.Close();
                            ScannerService_signatures.Close();

                            Logger.WriteLine("[ModuleVirusesDb] Закрытие потока");
                            CommandThread.Abort();
                            break;
                        }
                }
            }
        }


        /// <summary>
        /// Запуск коннектора
        /// </summary>
        public static void RunConnector()
        {
            CommandThread.Start();

            //Подключение к сервису сканирования
            ScannerService_signatures.Connect();
        }
    }





    /// <summary>
    /// База сигнатур
    /// </summary>
    public static class Db
    {
        static IsolatedStorageFile DbStorage;
        public static DbRecord[] DbTable = new DbRecord[] { };
        static Mutex DbSync = new Mutex();


        public static void InitDb()
        {
            Connectors.Logger.WriteLine("[InitDB] Init Isolated Storage!");

            DbStorage = IsolatedStorageFile.GetUserStoreForDomain();

            if (!DbStorage.DirectoryExists("VirusesDb"))
            {
                DbStorage.CreateDirectory("VirusesDb");
            }

            if (!Directory.Exists(Configurations.DatabaseFilesDir))
            {
                Connectors.Logger.WriteLine($"[InitDB] ВНИМАНИЕ! Создана папка {Configurations.DatabaseFilesDir}", LogLevel.WARN);
                Directory.CreateDirectory(Configurations.DatabaseFilesDir);
            }

            //Выгрузка баз из жесткого диска в изолированное хранилище
            LoadToIsolatedStorage("DatabaseFiles\\");
            string[] files = DbStorage.GetFileNames("VirusesDb\\*.db");

            if (files.Length > 0)
            {
                foreach (string file in files)
                {
                    Connectors.Logger.WriteLine("[InitDb] Загрузка базы ->" + file, LogLevel.WARN);
                    LoadDbFromFile("VirusesDb\\" + file);
                }

                Connectors.Logger.WriteLine($"[InitDb] Инициализация успешна, загружено {DbTable.Length} вирусов", LogLevel.OK);
            }
            else
            {
                Connectors.Logger.WriteLine("[InitDB] Файлы баз данных не найдены в изолированном хранилище", LogLevel.ERROR);
            }
        }

        /// <summary>
        /// Загрузить файлы БД из локального хранилища в изолированное
        /// </summary>
        /// <param name="localDir"></param>
        private static void LoadToIsolatedStorage(string localDir)
        {
            foreach(string file in DbStorage.GetFileNames("VirusesDb\\*.db"))
            {
                Connectors.Logger.WriteLine($"[LoadToIsolatedStorage] Удаление базы в изолированном хранилище {file}");
                DbStorage.DeleteFile("VirusesDb\\" + file);
            }

            Connectors.Logger.WriteLine("[LoadToIsolatedStorage] Загрузка файлов БД из локального в изолированное хранилище");

            string[] Files = Directory.GetFiles(localDir, "*.db");

            foreach(string file in Files)
            {
                Connectors.Logger.WriteLine($"[LoadToIsolatedStorage] Load file from >{file}< to >VirusesDb\\{file.Substring(file.LastIndexOf('\\') + 1)}<");

                var isolatedStorageFile = DbStorage.CreateFile($"VirusesDb\\{file.Substring(file.LastIndexOf('\\') + 1)}");
                var localStorageFile = File.Open(file, FileMode.Open);


                byte[] buffer = new byte[256];
                while(localStorageFile.Read(buffer, 0, buffer.Length) > 0)
                {
                    isolatedStorageFile.Write(buffer, 0, buffer.Length);
                }

                Connectors.Logger.WriteLine($"[LoadToIsolatedStorage] Load to isolated storage success", LogLevel.OK);
                isolatedStorageFile.Close();
                localStorageFile.Close();
            }
        }

        /// <summary>
        /// Загрузить БД из файла
        /// </summary>
        /// <param name="PathToFile"></param>
        private static void LoadDbFromFile(string PathToFile)
        {
            IsolatedStorageFileStream DbFile = DbStorage.OpenFile(PathToFile, FileMode.Open);
            BinaryReader reader = new BinaryReader(DbFile);

            byte[] signature;
            string name;

            int signatureLen = 0;
            VirusTypes type = 0;

            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                {
                    type = (VirusTypes)DbFile.ReadByte();
                    signatureLen = reader.ReadByte();

                    if (signatureLen == -1 || signatureLen == 0)
                    {
                        break;
                    }
                }

                {
                    signature = new byte[signatureLen];
                    DbFile.Read(signature, 0, signatureLen);
                }

                {
                    name = reader.ReadString();
                }

                DbSync.WaitOne();
                {
                    Array.Resize(ref DbTable, DbTable.Length + 1);
                    DbTable[DbTable.Length - 1] =
                        new DbRecord(
                            name,
                            signature,
                            type
                        );

                    Connectors.Logger.WriteLine($"[DbLoaderFromFile] Загружен вирус -> {name}, тип {type}, длина сигнатуры {signatureLen}", LogLevel.OK);
                }
                DbSync.ReleaseMutex();
            }

            DbFile.Close();
        }

        public struct DbRecord
        {
            public string Name;
            public byte[] Signature;
            public int Summ;
            public VirusTypes Type;

            public DbRecord(string name, byte[] signature, VirusTypes type = VirusTypes.Trojan)
            {
                this.Name = name;
                this.Signature = signature;
                this.Type = type;
                this.Summ = 0;

                foreach(byte i in signature)
                {
                    this.Summ += i;
                }
            }
        }

        public enum VirusTypes
        {
            Trojan,
            Worm,
            Cryptor,
            Unknown
        }
    }








    public static class Initializator
    {
        public static byte EntryPoint()
        {
#if DEBUG
            Connectors.Logger.Init();
#endif

            Db.InitDb();
            Connectors.RunConnector();

            return 0;
        }

        public static void Stop()
        {

        }
    }
}