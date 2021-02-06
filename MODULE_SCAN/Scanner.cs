﻿/*
    Наименование модуля: Scanner(Сканнер)
    Описание модуля
        Служит для проверки файлов
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.IO.IsolatedStorage;
using System.IO.Compression;
using System.IO.Pipes;
using System.IO.Ports;

using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using LoggerLib;

namespace MODULE__SCAN
{
    public static class Configuration
    {
        public static Encoding PipeEncoding = Encoding.Unicode;

        /// <summary>
        /// Максимальное количество задач сканирования
        /// </summary>
        public const int MAX_SCAN_TASKS = 10;

        /// <summary>
        /// Максимальный размер файла для быстрого сканирования (файл подходящий под такой критерий будет полностью считываться в память)
        /// </summary>
        public const int MAX_FAST_SCAN_FILE = 1_000_000_000;
    }


    public static class Connector
    {
        public static NamedPipeServerStream commandPipe = new NamedPipeServerStream("Scanner.CommandPipe");
        public static NamedPipeServerStream inputPipe = new NamedPipeServerStream("ScannerService.input");
        public static NamedPipeServerStream signaturesPipe = new NamedPipeServerStream("ScannerService.signatures");

        public static NamedPipeClientStream outputPipe = new NamedPipeClientStream("ScannerService.output");

        private static Thread inputHandler = new Thread(inputThread);
        private static Thread signatureHandler = new Thread(signatureThread);

        private static BinaryWriter outputWriter;

#if DEBUG
        public static LoggerClient Logger = new LoggerClient("Logger.Modules.Scanner", "Log");
#endif

        /// <summary>
        /// Записать данные о скане в выходящую трубу
        /// </summary>
        public static void ToOutput(int id, ScanResult result)
        {
            outputWriter.Write(id);
            outputWriter.Write((byte)result.Result);
            outputWriter.Write(result.VirusID);
            outputWriter.Flush();
        }

        /// <summary>
        /// Обработчик трубы по которой приходят пути к файлам для сканирования
        /// </summary>
        public static void inputThread()
        {
#if DEBUG
            Connector.Logger.WriteLine("[Scanner.inputThread] ScannerService.input wait connect");
#endif

            inputPipe.WaitForConnection();
            var binaryReader = new BinaryReader(inputPipe, Configuration.PipeEncoding);

#if DEBUG
            Connector.Logger.WriteLine("[Scanner.inputThread] ScannerService.input connected");
#endif

            while (true)
            {
                int id = binaryReader.ReadInt32();
                string file = binaryReader.ReadString();

                Connector.Logger.WriteLine($"[Scanner.inputThread] Add to scan, task id {id}, path -> {file}");
                ScanTasks.Add(id, file);
            }
        }

        public static void signatureThread()
        {
#if DEBUG
            Connector.Logger.WriteLine("[Scanner.signatureThread] Wait connect");
#endif

            signaturesPipe.WaitForConnection();
            var binaryReader = new BinaryReader(signaturesPipe);

#if DEBUG
            Connector.Logger.WriteLine("[Scanner.signatureThread] ScannerService.signatures connected");
#endif

            while (true)
            {
                var ID = binaryReader.ReadInt16();
                var Signature = binaryReader.ReadBytes(binaryReader.ReadInt16());

                if (ID >= Scanner.Signatures.Length)
                {
#if DEBUG
                    Connector.Logger.WriteLine("[Scanner.signatureThread] Write new signature to local buffer");
#endif

                    Array.Resize(ref Scanner.Signatures, Scanner.Signatures.Length + 1);
                    Scanner.Signatures[Scanner.Signatures.Length - 1] = new Signature(Signature);
                }
                else
                {
#if DEBUG
                    Connector.Logger.WriteLine("[Scanner.signatureThread] update signature on local buffer");
#endif

                    Scanner.Signatures[ID] = new Signature(Signature);
                }
            }
        }

        /// <summary>
        /// Инициализация коннектора
        /// </summary>
        public static void Init()
        {
#if DEBUG
            Logger.Init();
#endif

            inputHandler.Start();
            signatureHandler.Start();

            Logger.WriteLine("[Scanner.Init] Wait outputPipe connect", LogLevel.WARN);

            outputPipe.Connect();
            outputWriter = new BinaryWriter(outputPipe);

            Logger.WriteLine("[Scanner.Init] outputPipe connected", LogLevel.OK);
        }
    }

    public class ScanTask
    {
        public string file;
        public int id;

        public ScanTask(int id, string file, ScanTasks.ScanStart onStart, ScanTasks.ScanComplete onCompleted, Task task = null)
        {
            this.id = id;
            this.file = file;
        }
    }

    /// <summary>
    /// Содержит информацию о результате сканирования
    /// </summary>
    public class ScanResult
    {
        public readonly int VirusID;
        public readonly result Result;

        public ScanResult(int virusId, result res)
        {
            this.VirusID = virusId;
            this.Result = res;
        }
    }

    /// <summary>
    /// Результат сканирования
    /// </summary>
    public enum result
    {
        NotVirus,
        Virus,
        Error
    }

    /// <summary>
    /// Сигнатура
    /// </summary>
    public struct Signature
    {
        public readonly byte[] SignatureBytes;
        public readonly int Summ;

        public Signature(byte[] signature)
        {
            this.SignatureBytes = signature;
            this.Summ = 0;

            foreach (byte b in signature)
            {
                this.Summ += b;
            }
        }
    }

    public static class Scanner
    {
        public static Signature[] Signatures = new Signature[0];

        public static ScanResult ScanFile(Stream FileStream)
        {
            if (FileStream.Length <= Configuration.MAX_FAST_SCAN_FILE)
            {
                ScanResult Result = new ScanResult(0, result.NotVirus);

                byte[] FileBuffer = new byte[FileStream.Length];
                int readed = FileStream.Read(FileBuffer, 0, FileBuffer.Length);

                if (readed == 0)
                {
                    return Result;
                }

                Array.Resize(ref FileBuffer, readed);

                try
                {
                    Parallel.For(0, Signatures.Length, (int sigIndex, ParallelLoopState state) =>
                    {
                        int bufferSumm = 0;
                        int backOffset = Signatures[sigIndex].SignatureBytes.Length; //Задний оффсет, на каждой итерации делаем summ -= fileBuffer[bufPos - backOffset]

                        for (int initPos = 0; initPos < Signatures[sigIndex].SignatureBytes.Length; initPos++)
                        {
                            bufferSumm += FileBuffer[initPos];
                        }

                        for (int bufferPosition = backOffset; bufferPosition < FileBuffer.Length; bufferPosition++)
                        {
                            bufferSumm -= FileBuffer[bufferPosition - backOffset];
                            bufferSumm += FileBuffer[bufferPosition];

                            //Если сумма совпала, проверяем этот участок
                            if (bufferSumm == Signatures[sigIndex].Summ)
                            {
                                bool found = true;

                                for (
                                    int filePos = 1 + bufferPosition - backOffset, signaturePos = 0;
                                    filePos < bufferPosition && signaturePos < Signatures[sigIndex].SignatureBytes.Length;
                                    filePos++, signaturePos++)
                                {
                                    if (FileBuffer[filePos] != Signatures[sigIndex].SignatureBytes[signaturePos])
                                    {
                                        found = false;
                                        break;
                                    }
                                }

                                if (found)
                                {
                                    Result = new ScanResult(sigIndex, result.Virus);
                                    state.Break();
                                }
                            }
                        }
                    });
                }
                catch (Exception ex)
                {
                    Connector.Logger.WriteLine($"[Scanner] error {ex.Message}", LogLevel.ERROR);
                }

                return Result;
            }
            else
            {
                return new ScanResult(0, result.NotVirus);
            }
        }
    }

    public static class ScanTasks
    {
        public static Thread[] ScanThreads = new Thread[24];

        /// <summary>
        /// Очередь задач сканирования
        /// </summary>
        public static Queue<ScanTask> TaskQueue = new Queue<ScanTask>();
        public static Mutex TaskQueue_Sync = new Mutex();

        /// <summary>
        /// Количество активных задач сканирования
        /// </summary>
        public static byte ActiveScanTasks = 0;
        public static Mutex ActiveScanTasks_Sync = new Mutex();

        /// <summary>
        /// Мьютекс для сервиса сканнера
        /// </summary>
        public static Mutex ScanMutex = new Mutex();

        public delegate void ScanComplete(ScanTask task, ScanResult result);
        public delegate void ScanStart();

        /// <summary>
        /// При старте сканирования
        /// </summary>
        private static void ScanStarted()
        {
            ActiveScanTasks_Sync.WaitOne();
            {
                ActiveScanTasks++;
            }
            ActiveScanTasks_Sync.ReleaseMutex();
        }

        /// <summary>
        /// Событие окончания сканирования файла
        /// </summary>
        private static void ScanCompleted(ScanTask task, ScanResult result)
        {
            Connector.Logger.WriteLine($"\n\n[SCAN COMPLETE EVENT] {task.file}, result {result.Result}");

            ActiveScanTasks_Sync.WaitOne();
            {
                Connector.ToOutput(task.id, result);
                ActiveScanTasks--;
            }
            ActiveScanTasks_Sync.ReleaseMutex();
        }

        /// <summary>
        /// Добавить задачу сканирования
        /// </summary>
        /// <param name="pathToFile"></param>
        public static void Add(int id, string pathToFile)
        {
            TaskQueue_Sync.WaitOne();
            {
                TaskQueue.Enqueue(new ScanTask(id, pathToFile, ScanStarted, ScanCompleted));
            }
            TaskQueue_Sync.ReleaseMutex();
        }

        public static void ScanThread()
        {
            while (true)
            {
                TaskQueue_Sync.WaitOne();
                {
                    if (TaskQueue.Count > 0)
                    {
                        var task = TaskQueue.Dequeue();
                        TaskQueue_Sync.ReleaseMutex();

                        {
                            FileStream stream = null;

                            try
                            {
                                stream = File.Open(task.file, FileMode.Open);
                            }
                            catch (Exception ex)
                            {
                                Connector.Logger.WriteLine($"[SCANNER] ERROR OPEN FILE {ex.Message}", LogLevel.ERROR);
                                ScanCompleted(task, new ScanResult(0, MODULE__SCAN.result.Error));
                                continue;
                            }

                            Connector.Logger.WriteLine($"Thread start scan {Thread.CurrentThread.Name}", LogLevel.WARN);

                            var result = Scanner.ScanFile(stream);

                            stream.Close();
                            ScanCompleted(task, result);
                        }

                        continue;
                    }
                }
                TaskQueue_Sync.ReleaseMutex();

                Thread.Sleep(500);
            }
        }

        /// <summary>
        /// Инициализация сервиса
        /// </summary>
        public static void Init()
        {
            for (int index = 0; index < ScanThreads.Length; index++)
            {
                ScanThreads[index] = new Thread(ScanThread) { Name = index.ToString() };
                ScanThreads[index].Start();
            }
        }
    }

    public static class Initializator
    {
        public static byte EntryPoint()
        {
            ScanTasks.Init();
            new Thread(() => Connector.Init()).Start();

            return 0;
        }

        public static void Exit()
        {

        }
    }
}