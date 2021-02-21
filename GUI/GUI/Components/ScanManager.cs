using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;

using API_Client_Library;
using System.Diagnostics;

namespace GUI.Components.ScanManager
{
    static class ScanManager
    {
        const int MAX_SCAN_TASKS = 2000;

        private static MainForm MForm;
        private static Thread Thread1 = new Thread(ScanFilesLoader) { Name = "ScanFilesLoader" };

        /// <summary>
        /// Очередь файлов ожидающих сканирование
        /// </summary>
        public static Queue<string> FileQueue = new Queue<string>();
        public static Mutex FileQueue_sync = new Mutex();

        /// <summary>
        /// Количество всех файлов
        /// </summary>
        public static int CountAllFiles = 0;

        /// <summary>
        /// Количество отсканированных файлов
        /// </summary>
        public static int CountAllScannedFiles = 0;

        /// <summary>
        /// Активно сканируются
        /// </summary>
        public static int InScanProcess = 0;

        /// <summary>
        /// Последний отсканированный файл
        /// </summary>
        public static string LastScanned { get; set; }

        /// <summary>
        /// Расширения файлов, которые нужно проверять
        /// </summary>
        public static string ExtentionsFilter = "*.*"; //Для быстрой проверки использовать *.exe .dll .bat .vba .py .xlsx .docx

        /// <summary>
        /// Текущее состояние сканирования
        /// </summary>
        public static ScanState State = ScanState.Completed;

        /// <summary>
        /// Старт сканирования
        /// </summary>
        /// <param name="dirs"></param>
        public static void StartScan(string[] dirs, string[] files = null)
        {
            CountAllFiles = 0;
            CountAllScannedFiles = 0;

            State = ScanState.Active;

            FileQueue_sync.WaitOne();
            {
                foreach (string file in files)
                {
                    if (!File.Exists(file))
                    {
                        MainForm.Logger.WriteLine($"[StartScan] File {file} not exists, continue", LoggerLib.LogLevel.ERROR);
                        continue;
                    }

                    CountAllFiles++;
                    FileQueue.Enqueue(file);

                    MainForm.Logger.WriteLine($"[StartScan] Add {file} to queue");
                }
            }
            FileQueue_sync.ReleaseMutex();

            foreach (string dir in dirs)
            {
                new Task(() => AddAllFilesToScan(dir)).Start();
                MainForm.Logger.WriteLine($"[StartScan] Add to queue dir {dir}");
            }
        }

        private static void AddAllFilesToScan(string dir)
        {
            string[] dirs = Directory.GetDirectories(dir);

            if(dirs.Length != 0)
            {
                for (int index = 0; index < dirs.Length; index++)
                {
                    if (dirs[index] != null)
                    {
                        AddAllFilesToScan(dirs[index]);
                    }
                }
            }

            string[] files = new string[] { };

            try
            {
                files = Directory.GetFiles(dir, ExtentionsFilter, SearchOption.AllDirectories);
            }
            catch
            {
                MainForm.Logger.WriteLine($"[AddAllFilesToScan] Error getFiles, exit");
                return;
            }

            FileQueue_sync.WaitOne();
            {
                for (int index = 0; index < files.Length; index++)
                {
                    CountAllFiles++;
                    FileQueue.Enqueue(files[index]);
                }
            }
            FileQueue_sync.ReleaseMutex();
        }

        /// <summary>
        /// Поток который загружает файлы для сканирования в ядро
        /// </summary>
        private static void ScanFilesLoader()
        {
            MainForm.Logger.WriteLine($"[ScanFilesLoader] Running", LoggerLib.LogLevel.OK);

            while (true)
            {
                if (FileQueue.Count > 0 && InScanProcess <= MAX_SCAN_TASKS)
                {
                    FileQueue_sync.WaitOne();
                    {
                        var file = FileQueue.Dequeue();

                        MainForm.Logger.WriteLine($"[ScanFilesLoader] Add {file} to scan");

                        if (file != null)
                        {
                            API.AddToScan(file);
                        }
                        else
                        {
                            CountAllScannedFiles++;
                        }
                    }
                    FileQueue_sync.ReleaseMutex();
                }

                Thread.Sleep(50);
            }
        }

        /// <summary>
        /// Приостановить сканирование
        /// </summary>
        public static void Pause()
        {
            MainForm.Logger.WriteLine($"[ScanFilesLoader] Pause scan");
            FileQueue_sync.WaitOne();
        }

        /// <summary>
        /// Продолжить сканирование
        /// </summary>
        public static void Resume()
        {
            MainForm.Logger.WriteLine($"[ScanFilesLoader] Resume scan");
            FileQueue_sync.ReleaseMutex();
        }

        /// <summary>
        /// Отменить сканирование
        /// </summary>
        public static void Abort()
        {
            FileQueue_sync.WaitOne();
            {
                MainForm.Logger.WriteLine($"[ScanFilesLoader] Abort scan");

                FileQueue.Clear();
                API.ClearScanQueue();
            }
            FileQueue_sync.ReleaseMutex();
        }

        /// <summary>
        /// Сброс
        /// </summary>
        public static void Reset()
        {
            FileQueue.Clear();
            CountAllFiles = 0;
            CountAllScannedFiles = 0;
            InScanProcess = 0;

            State = ScanState.Completed;

            MainForm.Logger.WriteLine($"[ScanFilesLoader] Reset");
        }


        public static void Init(MainForm Form)
        {
            MForm = Form;
            Thread1.Start();
        }

        public static void Stop()
        {
            Thread1.Abort();
            State = ScanState.Aborted;
        }
    }





    public enum ScanState
    {
        Active,
        Pause,
        Aborted,
        Completed
    }
}
