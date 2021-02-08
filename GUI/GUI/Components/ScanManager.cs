using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;

using API_Client_Library;

namespace GUI.Components.ScanManager
{
    static class ScanManager
    {
        const int MAX_SCAN_TASKS = 10;

        private static MainForm MForm;
        private static Thread Thread1 = new Thread(Handler) { Name = "ScanManager" };

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

        public static List<VirusFileInfo> foundViruses = new List<VirusFileInfo>();

        /// <summary>
        /// Текущее состояние сканирования
        /// </summary>
        public static ScanState State = ScanState.Completed;

        /// <summary>
        /// Cтарт сканирования
        /// </summary>
        /// <param name="dir"></param>
        public static void StartScan(string dir)
        {
            CountAllFiles = 0;
            CountAllScannedFiles = 0;

            State = ScanState.Active;

            new Task(() => AddAllFilesToScan(dir)).Start();
        }

        /// <summary>
        /// Старт сканирования
        /// </summary>
        /// <param name="dirs"></param>
        public static void StartScan(string[] dirs)
        {
            CountAllFiles = 0;
            CountAllScannedFiles = 0;

            State = ScanState.Active;

            foreach (string dir in dirs)
            {
                new Task(() => AddAllFilesToScan(dir)).Start();
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

            string[] files = Directory.GetFiles(dir);

            for (int index = 0; index < files.Length; index++)
            {
                CountAllFiles++;
                FileQueue.Enqueue(files[index]);
            }
        }

        /// <summary>
        /// Поток который загружает файлы для сканирования в ядро
        /// </summary>
        private static void Handler()
        {
            while (true)
            {
                if (FileQueue.Count > 0 && InScanProcess <= MAX_SCAN_TASKS)
                {
                    var file = FileQueue.Dequeue();

                    if (file != null)
                    {
                        API.AddToScan(file);
                    }
                    else
                    {
                        CountAllScannedFiles++;
                    }
                }
            }
        }

        /// <summary>
        /// Приостановить сканирование
        /// </summary>
        public static void Pause()
        {
            FileQueue_sync.WaitOne();
        }

        /// <summary>
        /// Продолжить сканирование
        /// </summary>
        public static void Resume()
        {
            FileQueue_sync.ReleaseMutex();
        }

        /// <summary>
        /// Отменить сканирование
        /// </summary>
        public static void Abort()
        {

        }

        public static void Init(MainForm Form)
        {
            MForm = Form;

            API.onScanCompleted += API_onScanCompleted;
            API.onScanFound += API_onScanFound;
            Thread1.Start();
        }

        public static void Stop()
        {
            Thread1.Abort();
        }

        private static void API_onScanFound(VirusFileInfo File)
        {
            CountAllScannedFiles++;
            foundViruses.Add(File);
        }

        private static void API_onScanCompleted(ScannedFileInfo File)
        {
            CountAllScannedFiles++;
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
