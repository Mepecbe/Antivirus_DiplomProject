/*
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

namespace MODULE__SCAN
{
    public static class Configuration
    {
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
        public static NamedPipeServerStream inputPipe = new NamedPipeServerStream("ScannerService.input");
        public static NamedPipeServerStream signaturesPipe = new NamedPipeServerStream("ScannerService.signatures");

        public static NamedPipeClientStream outputPipe = new NamedPipeClientStream("ScannerService.output");

        private static Thread inputHandler = new Thread(inputThread);
        private static Thread signatureHandler = new Thread(signatureThread);

        private static StreamWriter outputWriter;
        private static StreamReader inputReader;
        private static StreamReader signatureReader;

        /// <summary>
        /// Записать данные в выходящую трубу
        /// </summary>
        public static async Task ToOutput(string file, ScanResult result)
        {
            await outputWriter.WriteLineAsync(file);
        }

        public static void inputThread()
        {
#if DEBUG
            Console.WriteLine("[Scanner.inputThread] ScannerService.input wait connect");
#endif

            inputPipe.WaitForConnection();
            inputReader = new StreamReader(inputPipe);

#if DEBUG
            Console.WriteLine("[Scanner.inputThread] ScannerService.input connected");
#endif

            while (true)
            {
                string file = inputReader.ReadLine();

                //new Task.Start(ScannerService.ScanFile(file))
            }
        }

        public static void signatureThread()
        {
#if DEBUG
            Console.WriteLine("[Scanner.signatureThread] Wait connect");
#endif

            signaturesPipe.WaitForConnection();
            signatureReader = new StreamReader(signaturesPipe);
            var binaryReader = new BinaryReader(signaturesPipe);

#if DEBUG
            Console.WriteLine("[Scanner.signatureThread] ScannerService.signatures connected");
#endif

            while (true)
            {
                var ID = binaryReader.ReadInt16();
                var Signature = binaryReader.ReadBytes(binaryReader.ReadInt16());

                if (ID >= Scanner.Signatures.Length)
                {
#if DEBUG
                    Console.WriteLine("[Scanner.signatureThread] write new signature to local buffer");
#endif

                    Array.Resize(ref Scanner.Signatures, Scanner.Signatures.Length + 1);
                    Scanner.Signatures[Scanner.Signatures.Length - 1] = new Signature(Signature);
                }
                else
                {
#if DEBUG
                    Console.WriteLine("[Scanner.signatureThread] update signature on local buffer");
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
            inputHandler.Start();
            signatureHandler.Start();

#if DEBUG
            Console.WriteLine("[Scanner.Init] Wait outputPipe connect");
#endif

            outputPipe.Connect();
            outputWriter = new StreamWriter(outputPipe);

#if DEBUG
            Console.WriteLine("[Scanner.Init] outputPipe connected");
#endif
        }
    }

    /// <summary>
    /// Содержит информацию о результате сканирования
    /// </summary>
    public class ScanResult
    {
        public readonly int VirusID;
        public readonly result Result;

        public ScanResult(int id, result res)
        {
            this.VirusID = id;
            this.Result = res;
        }
    }

    /// <summary>
    /// Результат сканирования
    /// </summary>
    public enum result
    {
        Virus,
        NotVirus,
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
                byte[] FileBuffer = new byte[Configuration.MAX_FAST_SCAN_FILE];
                FileStream.Read(FileBuffer, 0, FileBuffer.Length);

                ScanResult Result = new ScanResult(0, result.Virus);

                Parallel.For(0, Signatures.Length, (int sigIndex, ParallelLoopState state) =>
                {
                    int bufferSumm = 0;
                    int backOffset = Signatures[sigIndex].SignatureBytes.Length; //Задний оффсет, на каждой итерации делаем summ -= fileBuffer[bufPos - backOffset]

                    for (int initPos = 0; initPos < Signatures[sigIndex].SignatureBytes.Length; initPos++)
                    {
                        bufferSumm += FileBuffer[initPos];
                    }

                    for (int bufferPosition = backOffset; sigIndex < Signatures.Length; sigIndex++)
                    {
                        bufferSumm -= FileBuffer[bufferPosition - backOffset];
                        bufferSumm += FileBuffer[bufferPosition];

                        if (bufferSumm == Signatures[sigIndex].Summ)
                        {
                            Result = new ScanResult(sigIndex, result.Virus);
                            state.Break();
                        }
                    }
                });

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
        /// <summary>
        /// Задачи сканирования, ожидающие старта
        /// </summary>
        public static List<Task> AwaitedScanTasks = new List<Task>();
        public static Mutex AwaitedScanTasks_Sync = new Mutex();

        /// <summary>
        /// Количество активных задач сканирования
        /// </summary>
        public static byte ActiveScanTasks = new byte();
        public static Mutex ActiveScanTasks_Sync = new Mutex();

        private static Random Generator = new Random();

        public delegate void ScanComplete(string filename, ScanResult result);
        public static event ScanComplete OnScanCompleted;


        private static int getId()
        {
            return 0;
        }

        /// <summary>
        /// Запустить сколько возможно новых задач сканирования (всё упирается в лимит установленный конфигурацией)
        /// </summary>
        private static void UpdateActiveTasks()
        {
            ActiveScanTasks_Sync.WaitOne();

            for (int index = 0; index < AwaitedScanTasks.Count; index++)
            {
                AwaitedScanTasks[index].Start();
                AwaitedScanTasks.RemoveAt(index);
            }

            ActiveScanTasks_Sync.ReleaseMutex();
        }

        /// <summary>
        /// Создать задачу сканирования
        /// </summary>
        private static Task CreateTask(string file)
        {
            return new Task(() =>
            {
                if (File.Exists(file))
                {
#if DEBUG
                    Console.WriteLine($"[ScanFile] START SCAN FILE {file}");
#endif
                    var FileStrm = File.Open(file, FileMode.Open);
                    var result = Scanner.ScanFile(FileStrm);
                    FileStrm.Close();

                    OnScanCompleted?.Invoke(file, result);
                }
            });
        }

        /// <summary>
        /// Событие окончания сканирования файла
        /// </summary>
        private static void ScanCompleted(string filename, ScanResult result)
        {
            Console.WriteLine($"[SCAN COMPLETE EVENT] {filename}");
            UpdateActiveTasks();
        }

        /// <summary>
        /// Добавить задачу сканирования
        /// </summary>
        /// <param name="pathToFile"></param>
        public static void Add(string pathToFile)
        {
            if (ActiveScanTasks < Configuration.MAX_SCAN_TASKS)
            {
                ActiveScanTasks_Sync.WaitOne();
                int id = getId();

                var newTask = CreateTask(pathToFile);
                newTask.Start();
            }
            else
            {
                AwaitedScanTasks_Sync.WaitOne();
                var newTask = CreateTask(pathToFile);
                AwaitedScanTasks.Add(newTask);
            }
        }


        public static void Init()
        {
            OnScanCompleted += ScanCompleted;
        }
    }

    public static class Initializator
    {
        public static byte EntryPoint()
        {

            ScanTasks.Init();

            new Task(() => Connector.Init()).Start();
            return 0;
        }

        public static void Exit()
        {

        }
    }
}