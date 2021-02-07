using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

using Core.Kernel.Connectors;
using Core.Kernel.Configurations;
using Core.Kernel.VirusesManager;
using Core.Kernel.ErrorTasks;

namespace Core.Kernel.ScanModule
{
    /// <summary>
    /// Обработчик ответов с результатами сканирования от сервиса скана
    /// </summary>
    static class ScannerResponseHandler
    {
        public delegate void ScanCompletedEvent(int id, bool found, int virusId, string file);
        public static event ScanCompletedEvent onScanCompleted;


        private static NamedPipeServerStream Connector = Connectors.KernelConnectors.ScannerService_Input;
        public static Thread InputThreadHandler = new Thread(InputHandler);


        private static void InputHandler()
        {
            KernelConnectors.Logger.WriteLine("[ScannerResponseHandler.InputHandler] Started");

            while (true)
            {
                Connectors.KernelConnectors.ScannerService_Input_Sync.WaitOne();
                {
                    int id = KernelConnectors.ScannerService_Reader.ReadInt32();
                    byte result = KernelConnectors.ScannerService_Reader.ReadByte();
                    int virusId = KernelConnectors.ScannerService_Reader.ReadInt32();
                    var task = ScanTasks.getTaskById(id);

                    if (task is null)
                    {
                        KernelConnectors.Logger.WriteLine($"[ScannerResponseHandler.InputHandler] Задача сканирования {id} не найдена", LoggerLib.LogLevel.ERROR);
                        continue;
                    }

                    if (result == 2)
                    {
                        KernelConnectors.Logger.WriteLine($"[ScannerResponseHandler.InputHandler] Задача сканирования {id} не была выполнена, новая попытка {task.ProbesCount}", LoggerLib.LogLevel.ERROR);

                        if (task.ProbesCount >= 5)
                        {
                            KernelConnectors.Logger.WriteLine($"[ScannerResponseHandler.InputHandler] Задача сканирования {id} не была выполнена спустя 5 попыток", LoggerLib.LogLevel.ERROR);
                            ErrorScanTasksManager.Add(1, "Message", task);

                            onScanCompleted.Invoke(id, false, 0, task.File);
                        }
                        else
                        {
                            task.ProbesCount++;
                            new Task(() =>
                            {
                                Thread.Sleep(TimeSpan.FromSeconds(2));
                                ScanTasks.RestartScan(id);
                            }).Start();
                        }

                        continue;
                    }

                    onScanCompleted.Invoke(id, result == 1, virusId, task.File);
                }
                KernelConnectors.ScannerService_Input_Sync.ReleaseMutex();
            }
        }

        public static void Init()
        {
            InputThreadHandler.Start();
        }
    }

    /// <summary>
    /// Обработчик подключаемого фильтра
    /// </summary>
    static class FilterHandler
    {
        /// <summary>
        /// Обработчик обнаруженных файлов от фильтра
        /// </summary>
        private static readonly Thread FilterMonitor = new Thread(() =>
        {
            KernelConnectors.Logger.WriteLine("[FileQueue] [Thr.Monitor] Started, wait sync mutex... ");

            KernelConnectors.Filter_Input_Sync.WaitOne();
            {
                if (KernelConnectors.Filter_Input.IsConnected)
                {
                    KernelConnectors.Logger.WriteLine("[FileQueue] [Thr.Monitor] CONNECTED ");
                }
            }
            KernelConnectors.Filter_Input_Sync.ReleaseMutex();

            while (true)
            {
                string commandBuffer = KernelConnectors.Filter_Reader.ReadString();

                if (FoundVirusesManager.Exists(commandBuffer.Substring(1)))
                {
                    //Если файл уже числится у нас как вирус
                    continue;
                }

                switch (commandBuffer[0])
                {
                    case '1': 
                        {
                            KernelConnectors.Logger.WriteLine("[FileQueue] [Thr.Monitor] Created file -> " + commandBuffer);

                            ScanTasks.Add(commandBuffer.Substring(1));
                            break; 
                        }

                    case '4': 
                        {
                            KernelConnectors.Logger.WriteLine("[FileQueue] [Thr.Monitor] Changed file -> " + commandBuffer);

                            ScanTasks.Add(commandBuffer.Substring(1));
                            break; 
                        }
                }

                commandBuffer = string.Empty;
            }
        });


        public static void Run()
        {
            FilterMonitor.Start();
        }
    }


    /// <summary>
    /// Менеджер задач сканирования
    /// </summary>
    public static class ScanTasks
    {
        public static int id = 0;

        public static NamedPipeClientStream Scanner_Output;
        public static BinaryWriter ScannerBinaryWriter;

        public static List<ScanTask> tasks = new List<ScanTask>();
        public static Mutex tasks_sync = new Mutex();

        public static ScanTask Add(string file)
        {
            ScanTask task = null;

            tasks_sync.WaitOne();
            {
                task = new ScanTask(file, id);
                tasks.Add(task);

                ScannerBinaryWriter.Write(id);
                ScannerBinaryWriter.Write(file);

                KernelConnectors.Logger.WriteLine("write", LoggerLib.LogLevel.WARN);

                ScannerBinaryWriter.Flush();

                id++;
            }
            tasks_sync.ReleaseMutex();

            return task;
        }

        public static void RestartScan(int taskId)
        {
            var task = getTaskById(taskId);

            tasks_sync.WaitOne();
            {
                ScannerBinaryWriter.Write(taskId);
                ScannerBinaryWriter.Write(task.File);
                ScannerBinaryWriter.Flush();
            }
            tasks_sync.ReleaseMutex();
        }

        /// <summary>
        /// Удалить задачу по айди
        /// </summary>
        public static void RemoveById(int id)
        {
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
            {
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

                    KernelConnectors.Logger.WriteLine("[ScanQueue] Virus found!");
                }
                else
                {
                    KernelConnectors.Logger.WriteLine("[ScanQueue] ERROR, TASK NOT FOUND!");
                }
            }
            else
            {
                KernelConnectors.Logger.WriteLine($"[ScanQueue] Not virus {id}!");
            }

            
            RemoveById(id);
        }


        /// <summary>
        /// Инициализация менеджера задач сканирования
        /// </summary>
        public static void Init()
        {
            FilterHandler.Run();

            ScannerResponseHandler.onScanCompleted += ScanCompleted;

            Scanner_Output = KernelConnectors.ScannerService_Output;
            ScannerBinaryWriter = new BinaryWriter(Scanner_Output, KernelInitializator.Config.NamedPipeEncoding);
        }
    }

       








    /// <summary>
    /// Представляет собой задачу сканирования
    /// </summary>
    public class ScanTask
    {
        public string File;
        public int TaskId;

        /// <summary>
        /// Количество попыток сканирования
        /// </summary>
        public byte ProbesCount;

    
        public ScanTask(string file, int id)
        {
            this.File = file;
            this.TaskId = id;
            ProbesCount = 0;
        }
    }
}
