using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;
using System.IO.IsolatedStorage;

namespace MODULE__VIRUSES_DB
{
    public static class Connectors
    {
        public static NamedPipeServerStream VirusesDb_CommandPipe = new NamedPipeServerStream("VirusesDb.CommandPipe");
        public static NamedPipeClientStream ScannerService_signatures = new NamedPipeClientStream("ScannerService.signatures");

        public static Thread CommandThread = new Thread(commandHandler);

        private static void commandHandler()
        {
#if DEBUG
            Console.WriteLine($"[ModuleVirusesDb.Connectors.commandThread] Wait connect");
#endif
            VirusesDb_CommandPipe.WaitForConnection();
#if DEBUG
            Console.WriteLine($"[ModuleVirusesDb.Connectors.commandThread] Connected");
#endif

            StreamReader pipeReader = new StreamReader(VirusesDb_CommandPipe, Encoding.Unicode);
            BinaryWriter writer = new BinaryWriter(ScannerService_signatures);

            while (true)
            {
#if DEBUG
                Console.WriteLine($"[ModuleVirusesDb.Connectors.commandThread] WAIT COMMAND");
#endif
                string command = pipeReader.ReadLine();

#if DEBUG
                Console.WriteLine($"[ModuleVirusesDb.Connectors.commandThread] READ LINE");
#endif

                switch (command)
                {
                    case "/reinit_db":
                        {
#if DEBUG
                            Console.WriteLine("[ModuleVirusesDb] reinit_db");
#endif
                            break;
                        }

                    case "/upload_to_scanner":
                        {
#if DEBUG
                            Console.WriteLine("[ModuleVirusesDb] UPLOAD TO SCANNER ALL SIGNATURES");
#endif

                            for(int index = 0; index < Db.DbTable.Length; index++)
                            {
                                writer.Write(Convert.ToInt16(index));
                                writer.Write(Convert.ToInt16(Db.DbTable[index].Signature.Length));
                                
                                writer.Write(Db.DbTable[index].Signature);                                

                                writer.Flush();
                            }

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

#if DEBUG
            Console.WriteLine($"[ModuleViruses.Connectors.RunConnector] Wait connect to ScannerService.signatures");
#endif

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
#if DEBUG
            Console.WriteLine("[InitDB] Init Isolated Storage!");

#endif

            DbStorage = IsolatedStorageFile.GetUserStoreForDomain();

            if (!DbStorage.DirectoryExists("VirusesDb"))
            {
                DbStorage.CreateDirectory("VirusesDb");
#if DEBUG
                Console.WriteLine("[InitDB] Created Directory VirusesDb in Isolated Storage");
#endif
            }


            LoadToIsolatedStorage("DatabaseFiles\\");


            string[] files = DbStorage.GetFileNames("VirusesDb\\*.db");

            if (files.Length > 0)
            {
                foreach (string file in files)
                {
#if DEBUG
                    Console.WriteLine("[InitDb] Load Db ->" + file);
#endif
                    LoadDbFromFile("VirusesDb\\" + file);
                }

#if DEBUG
                Console.WriteLine($"[InitDb] End init, loaded {DbTable.Length} viruses");
#endif
            }
            else
            {
#if DEBUG
                Console.WriteLine("[InitDB] DB files in isolated storage not found");
#endif
            }
        }

        /// <summary>
        /// Загрузить файлы БД из локального хранилища в изолированное
        /// </summary>
        /// <param name="localDir"></param>
        private static void LoadToIsolatedStorage(string localDir)
        {
#if DEBUG
            Console.WriteLine("[LoadToIsolatedStorage] Load DBs File from local storage to isolated storage");
#endif
            string[] Files = Directory.GetFiles(localDir, "*.db");

            foreach(string file in Files)
            {
#if DEBUG
                Console.WriteLine($"[LoadToIsolatedStorage] Load file from >{file}< >VirusesDb\\{file.Substring(file.LastIndexOf('\\') + 1)}<");
#endif

                var isolatedStorageFile = DbStorage.CreateFile($"VirusesDb\\{file.Substring(file.LastIndexOf('\\') + 1)}");
                var localStorageFile = File.Open(file, FileMode.Open);


                byte[] buffer = new byte[256];
                while(localStorageFile.Read(buffer, 0, buffer.Length) > 0)
                {
                    isolatedStorageFile.Write(buffer, 0, buffer.Length);
                }

                Console.WriteLine($"[LoadToIsolatedStorage] Load success");
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


            while ( (type = (VirusTypes)DbFile.ReadByte()) > 0)
            {
                {
                    signatureLen =  reader.ReadByte();

                    if (signatureLen == -1)
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

#if DEBUG
                    Console.WriteLine($"[DbLoaderFromFile] load virus -> {name}, type {type}, signature len {signatureLen}");
#endif
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
            Unknown,
            Trojan,
            Worm,
            Cryptor
        }
    }





    public static class Initializator
    {
        public static byte EntryPoint()
        {
            Db.InitDb();
            Connectors.RunConnector();

            return 0;
        }

        public static void Stop()
        {

        }
    }
}