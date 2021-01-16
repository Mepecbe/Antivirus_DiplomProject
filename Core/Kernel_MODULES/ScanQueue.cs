using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Core.Kernel.ScanModule
{
    /// <summary>
    /// Класс, который реализует очереди сканирования
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
        /// По этой трубе происходит приём имен файлов от модуля фильтра
        /// </summary>
        private static NamedPipeServerStream FilterPipe = new NamedPipeServerStream("FILE_QUEUE");

        private static readonly Thread Monitor = new Thread(() =>
        {
#if DEBUG
            Console.WriteLine("[FileQueue] [Thr.Monitor] Wait connection... ");
#endif
            FilterPipe.WaitForConnection();
#if DEBUG
            Console.WriteLine("[FileQueue] [Thr.Monitor] CONNECTED ");
#endif

            var Reader = new StreamReader(FilterPipe, Configuration.Configuration.NamedPipeEncoding);

            while(true)
            {
                string commandBuffer = Reader.ReadLine();

                Console.WriteLine("[FileQueue] [Thr.Monitor] ->" + commandBuffer);
               
                switch (commandBuffer[0])
                {
                    case '1': 
                        {
#if DEBUG
                            Console.WriteLine("[FileQueue] [Thr.Monitor] Created file -> " + commandBuffer);
#endif
                            break; 
                        }

                    case '4': 
                        {
#if DEBUG
                            Console.WriteLine("[FileQueue] [Thr.Monitor] Changed file -> " + commandBuffer);
#endif
                            break; 
                        }
                }

                commandBuffer = string.Empty;
            }
        });


        public static void Run()
        {
            Monitor.Start();
        }
    }
}
