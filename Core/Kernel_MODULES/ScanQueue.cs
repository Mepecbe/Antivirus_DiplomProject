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
        public delegate void ScanCompletedEvent(int id, bool found, int virusId, string file);
        public static event ScanCompletedEvent onScanCompleted;


        private static NamedPipeServerStream Connector = Connectors.KernelConnectors.Filter_Input;
        public static Thread InputThreadHandler = new Thread(InputHandler);

        private static void InputHandler()
        {
            Console.WriteLine("[ScannerResponseHandler.InputHandler] Started");

            var reader = new BinaryReader(Connector);

            while (true)
            {
                Connectors.KernelConnectors.ScannerService_Input_Sync.WaitOne();
                {
                    int id = reader.ReadInt32();
                    byte result = reader.ReadByte();
                    int virusId = reader.ReadInt32();
                    var task = ScanTasks.getTaskById(id);

                    onScanCompleted.Invoke(id, result != 0, virusId, task.File);
                }
                KernelConnectors.ScannerService_Input_Sync.ReleaseMutex();
            }
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


        public static ScanTask Add(string file)
        {
            tasks_sync.WaitOne();
                var task = new ScanTask(file, tasks.Count);
                tasks.Add(task);

                //Console.WriteLine($"[Add] Created task, id {task.TaskId}, file {task.File}");
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
            //Console.WriteLine($"RemoveTaskId {id}");
            //Console.WriteLine($"Count tasks {tasks.Count}");

            tasks_sync.WaitOne();
            {
                for (int taskIndex = 0; taskIndex < tasks.Count; taskIndex++)
                {
                    if (tasks[taskIndex].TaskId == id)
                    {
                        tasks.RemoveAt(taskIndex);
                        break;
                    }
                }
            }
            tasks_sync.ReleaseMutex();
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

        /// <summary>
        /// Получить экземпляр задачи
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public static ScanTask getTaskById(int id)
        {
            tasks_sync.WaitOne();
            for (int index = 0; index < tasks.Count; index++)
            {
                if (tasks[index].TaskId == id)
                {
                    var task = tasks[index];

                    tasks_sync.ReleaseMutex();

                    return task;
                }
            }
            tasks_sync.ReleaseMutex();

            return null;
        }

        /// <summary>
        /// Извлечь задачу и удалить из листа задач
        /// </summary>
        public static ScanTask getTaskAndRemove(int id)
        {
            tasks_sync.WaitOne();
            for (int index = 0; index < tasks.Count; index++)
            {
                if (tasks[index].TaskId == id)
                {
                    var task = tasks[index];

                    tasks.RemoveAt(index);
                    tasks_sync.ReleaseMutex();

                    return task;
                }
            }
            tasks_sync.ReleaseMutex();

            return null;
        }


        public static void ScanCompleted(int id, bool found, int virusId, string file)
        {
            if (found)
            {
                var task = getTaskAndRemove(id);

                if (task != null)
                {
                    FoundVirusesManager.AddNewVirus(
                        new VirusInfo(
                            id,
                            task.File,
                            virusId
                        )
                    );

                    Console.WriteLine("[ScanQueue] Virus found!");
                }
                else
                {
                    Console.WriteLine("[ScanQueue] ERROR, TASK NOT FOUND!");
                }
            }
            else
            {
                Console.WriteLine($"[ScanQueue] Not virus {id}!");
            }

            RemoveById(id);
        }


        /// <summary>
        /// Инициализация менеджера задач сканирования
        /// </summary>
        public static void Init()
        {
            ScannerResponseHandler.onScanCompleted += ScanCompleted;

            Scanner_Output = KernelConnectors.ScannerService_Output;
            ScannerBinaryWriter = new BinaryWriter(Scanner_Output);
        }
    }




    /// <summary>
    /// Класс отвечающий за найденные вирусы
    /// </summary>
    public static class FoundVirusesManager
    {
        public static List<VirusInfo> VirusesTable = new List<VirusInfo>();
        public static Mutex VirusesTable_sync = new Mutex();

        /// <summary>
        /// Добавить новый вирус в таблицу
        /// </summary>
        /// <param name="info"></param>
        public static void AddNewVirus(VirusInfo info)
        {
            VirusesTable_sync.WaitOne();
            {
                VirusesTable.Add(info);
            }
            VirusesTable_sync.ReleaseMutex();
        }

        /// <summary>
        /// Инициализация компонента
        /// </summary>
        public static void Init()
        {

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

    public class VirusInfo
    {
        public int id;
        public string file;
        public int VirusId;

        public VirusInfo(int id, string file, int VirusId)
        {
            this.id = id;
            this.file = file;
            this.VirusId = VirusId;
        }
    }
}
