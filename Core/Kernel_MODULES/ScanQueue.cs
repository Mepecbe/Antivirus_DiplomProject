using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Core.Kernel_MODULES.ScanModule
{
    /// <summary>
    /// Класс, который реализует очереди сканирования
    /// Служит промежутком между сервисом сканирования файлов и модулем связи с драйверами и модулем диспетчера съемных носителей  
    /// </summary>
    static class ScanQueue
    {
        


    }

    /// <summary>
    /// Хранит в себе очередь обнаруженных файлов
    /// </summary>
    static class FileQueue
    {
        /// <summary>
        /// По этой трубе происходит приём имен файлов от модуля отслеживания файлов через драйвер
        /// </summary>
        private static NamedPipeServerStream driverFileMon = new NamedPipeServerStream("FileNamePipe");

        /// <summary>
        /// По этой трубе происходит приём имен файлов от модуля отслеживания файлов по API
        /// </summary>
        private static NamedPipeServerStream reserveFileMon = new NamedPipeServerStream("PartitionMon_FilePaths");

        private static readonly Thread DriverMonitorPipe = new Thread(() =>
        {
#if DEBUG
            Console.WriteLine("[FileQueue] [Thr.DriverMonitorPipe] Wait connection... ");
#endif
            driverFileMon.WaitForConnection();
#if DEBUG
            Console.WriteLine("[FileQueue] [Thr.DriverMonitorPipe] CONNECTED ");
#endif

            byte[] buffer = new byte[256];
            while (driverFileMon.Read(buffer, 0, buffer.Length) > 0)
            {
#if DEBUG
                Console.WriteLine("[FileQueue] [Thr.DriverMonitorPipe] Read command");
#endif
            }

#if DEBUG
            Console.WriteLine("END");
#endif
        });

        private static readonly Thread APIMonitor = new Thread(() =>
        {
#if DEBUG
            Console.WriteLine("[FileQueue] [Thr.APIMonitorPipe] Wait connection... ");
#endif
            reserveFileMon.WaitForConnection();
#if DEBUG
            Console.WriteLine("[FileQueue] [Thr.APIMonitorPipe] CONNECTED ");
#endif

            var Reader = new StreamReader(reserveFileMon, Configuration.Configuration.NamedPipeEncoding);

            while(true)
            {
                string commandBuffer = Reader.ReadLine();

                Console.WriteLine("[FileQueue] [Thr.APIMonitorPipe] ->" + commandBuffer);
               
                switch (commandBuffer[0])
                {
                    case '1': 
                        {
#if DEBUG
                            Console.WriteLine("[FileQueue] [Thr.APIMonitorPipe] Created file -> " + commandBuffer);
#endif
                            break; 
                        }

                    case '4': 
                        {
#if DEBUG
                            Console.WriteLine("[FileQueue] [Thr.APIMonitorPipe] Changed file -> " + commandBuffer);
#endif
                            break; 
                        }
                }

                commandBuffer = string.Empty;
            }
        });


        public static void RunDriverMonitorPipe()
        {
            DriverMonitorPipe.Start();
        }

        public static void RunAPIMonitorPipe()
        {
            APIMonitor.Start();
        }
    }
}
