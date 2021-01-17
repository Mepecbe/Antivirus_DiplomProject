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
        public static NamedPipeServerStream CommandPipe = new NamedPipeServerStream("VirusesDb_CommandPipe");
        public static NamedPipeServerStream DataPipe = new NamedPipeServerStream("VirusesDb_DataPipe");

        public static Thread CommandThread = new Thread(commandHandler);
        public static Thread DataThread    = new Thread(dataHandler);

        private static void commandHandler()
        {
#if DEBUG
            Console.WriteLine($"[ModuleVirusesDb.Connectors.commandThread] Wait connect");
#endif
            CommandPipe.WaitForConnection();

            while (true)
            {

            }
        }

        private static void dataHandler()
        {
#if DEBUG
            Console.WriteLine($"[ModuleVirusesDb.Connectors.dataPipe] Wait connect");
#endif
            DataPipe.WaitForConnection();

            while (true)
            {

            }

        }

        /// <summary>
        /// Запуск коннектора
        /// </summary>
        public static void RunConnector()
        {
            CommandThread.Start();
            DataThread.Start();
        }
    }



    public static class Db
    {
        static IsolatedStorageFile DbStorage;

        public static void InitDb()
        {
#if DEBUG
            Console.WriteLine("[InitDB] Init Isolated Storage!");
#endif

            DbStorage = IsolatedStorageFile.GetUserStoreForDomain();

            if (!DbStorage.DirectoryExists("VirusesDb"))
            {
                Console.WriteLine("[InitDB] ");
                return;
            }

#if DEBUG
            Console.WriteLine("Load DB File");
#endif

            string[] dirs = DbStorage.GetDirectoryNames();

            foreach(string dir in dirs)
            {
                Console.WriteLine(dir);
            }
        }

        public struct DbRecord
        {
            public string Name;
            public byte[] Signature;
            public VirusTypes Type;
        }

        public enum VirusTypes
        {
            Trojan,
            Worm,
            Cryptor
        }
    }





    public static class Initializator
    {
        public static byte EntryPoint()
        {
            Connectors.RunConnector();
            Db.InitDb();

            return 0;
        }

        public static void Stop()
        {

        }
    }
}
