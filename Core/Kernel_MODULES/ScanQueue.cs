using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Core.Kernel.Connectors;

namespace Core.Kernel.ScanModule
{
    /// <summary>
    /// Обработчик ответов с результатами сканирования от сервиса скана
    /// </summary>
    static class ScannerResponseHandler
    {
        private static NamedPipeServerStream Connector = Connectors.KernelConnectors.Filter_Input;
        public static Thread InputThreadHandler = new Thread(InputHandler);

        private static void InputHandler()
        {
            Console.WriteLine("[InputHandler] Started");
            Connectors.KernelConnectors.ScannerService_Input_Sync.WaitOne();

            var reader = new BinaryReader(Connector);

            while (true)
            {
                Console.WriteLine("[InputHandler] WAIT RESPONSE FROM SCANNER");

                int id = reader.ReadInt32();
                byte result = reader.ReadByte();
                int virusId = reader.ReadInt32();

                Console.WriteLine($"[KERNEL.SCANQUEUE] READ RESULT FROM SCANNER, id {id}, result {result}, virus {virusId}");
            }

            KernelConnectors.ScannerService_Input_Sync.ReleaseMutex();
        }

        public static void Init()
        {
            Connector = Connectors.KernelConnectors.ScannerService_Input;
            InputThreadHandler.Start();
        }
    }

    /// <summary>
    /// Обработчик подключаемого фильтра
    /// </summary>
    static class FilterHandler
    {
        private static NamedPipeServerStream FilterConnector;

        /// <summary>
        /// Обработчик обнаруженных файлов от фильтра
        /// </summary>
        private static readonly Thread FilterMonitor = new Thread(() =>
        {
#if DEBUG
            Console.WriteLine("[FileQueue] [Thr.Monitor] Started, wait sync mutex... ");
#endif
            Connectors.KernelConnectors.Filter_Input_Sync.WaitOne();
            if (Connectors.KernelConnectors.Filter_Input.IsConnected)
            {
#if DEBUG
                Console.WriteLine("[FileQueue] [Thr.Monitor] CONNECTED ");
#endif
                Connectors.KernelConnectors.Filter_Input_Sync.ReleaseMutex();
            }

            var Reader = new StreamReader(FilterConnector, Configuration.Configuration.NamedPipeEncoding);

            while(true)
            {
                string commandBuffer = Reader.ReadLine();

#if DEBUG
                //Console.WriteLine("[FileQueue] [Thr.Monitor] ->" + commandBuffer);
#endif

                switch (commandBuffer[0])
                {
                    case '1': 
                        {
#if DEBUG
                            Console.WriteLine("[FileQueue] [Thr.Monitor] Created file -> " + commandBuffer);
#endif

                            ScanTasks.Add(commandBuffer.Substring(1));
                            break; 
                        }

                    case '4': 
                        {
#if DEBUG
                            Console.WriteLine("[FileQueue] [Thr.Monitor] Changed file -> " + commandBuffer);
#endif

                            ScanTasks.Add(commandBuffer.Substring(1));
                            break; 
                        }
                }

                commandBuffer = string.Empty;
            }
        });


        public static void Run()
        {
            FilterConnector = KernelConnectors.Filter_Input;
            FilterMonitor.Start();
        }
    }


    /// <summary>
    /// Менеджер задач сканирования
    /// </summary>
    public static class ScanTasks
    {
        public static NamedPipeClientStream Scanner_Output;
        public static BinaryWriter ScannerBinaryWriter;

        public static List<ScanTask> tasks = new List<ScanTask>();
        public static Mutex tasks_sync = new Mutex();

        /// <summary>
        /// Если сканнер обнаружил сигнатуру вируса в файле
        /// </summary>
        public delegate void ScanResult(string file, bool found, int virusId);

        public static event ScanResult onScanCompleted;


        public static ScanTask Add(string file)
        {
            tasks_sync.WaitOne();

                Console.WriteLine("[Add] Create");
                var task = new ScanTask(file, tasks.Count);
                tasks.Add(task);

                Console.WriteLine($"[Add] SEND DATA, new task id {task.TaskId}, file {task.File}");
                ScannerBinaryWriter.Write(task.TaskId);
                ScannerBinaryWriter.Write(file);
                ScannerBinaryWriter.Flush();


            tasks_sync.ReleaseMutex();

            return task;
        }

        /// <summary>
        /// Удалить задачу по айди
        /// </summary>
        public static void RemoveById(int id)
        {
            tasks.RemoveAt(id);
        }

        /// <summary>
        /// Удалить по полному пути к файлу
        /// </summary>
        public static void RemoveByFileName(string file)
        {
            tasks_sync.WaitOne();
            for(int index = 0; index < tasks.Count; index++)
            {
                if(tasks[index].File == file)
                {
                    tasks.RemoveAt(index);
                    break;
                }
            }
            tasks_sync.ReleaseMutex();
        }



        public static void ScanEnded(int id, bool found, int virusId)
        {
            Console.WriteLine("[SCANQUEUE.ScanEnded] ");
        }



        public static void Init()
        {
            Scanner_Output = KernelConnectors.ScannerService_Output;

            ScannerBinaryWriter = new BinaryWriter(Scanner_Output);
        }
    }














    /// <summary>
    /// Представляет собой задачу сканирования
    /// </summary>
    public class ScanTask
    {
        public string File;
        public int TaskId;
    
        public ScanTask(string file, int id)
        {
            this.File = file;
            this.TaskId = id;
        }
    }
}
