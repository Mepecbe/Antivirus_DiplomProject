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

        private static BinaryWriter outputWriter;
        private static StreamReader inputReader;

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
        /// 
        /// </summary>
        public static void inputThread()
        {
#if DEBUG
            Console.WriteLine("[Scanner.inputThread] ScannerService.input wait connect");
#endif

            inputPipe.WaitForConnection();
            inputReader = new StreamReader(inputPipe, Encoding.Unicode);
            var binaryReader = new BinaryReader(inputPipe);

#if DEBUG
            Console.WriteLine("[Scanner.inputThread] ScannerService.input connected");
#endif

            while (true)
            {
                int id = binaryReader.ReadInt32();
                string file = binaryReader.ReadString();

                Console.WriteLine($"[Scanner.inputThread] Add to scan, task id {id}, path -> {file}");
                ScanTasks.Add(id, file);
            }
        }

        public static void signatureThread()
        {
#if DEBUG
            Console.WriteLine("[Scanner.signatureThread] Wait connect");
#endif

            signaturesPipe.WaitForConnection();
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
                    Console.WriteLine("[Scanner.signatureThread] Write new signature to local buffer");
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
            outputWriter = new BinaryWriter(outputPipe);

#if DEBUG
            Console.WriteLine("[Scanner.Init] outputPipe connected");
#endif
        }
    }

    public class ScanTask
    {
        public Task task;
        public string file;
        public int id;

        public ScanTask(int id, string file, ScanTasks.ScanStart onStart, ScanTasks.ScanComplete onCompleted, Task task = null)
        {
            this.id = id;
            this.file = file;
            
            if (task is null)
            {
                this.task = new Task(() =>
                {
                    if (File.Exists(file))
                    {
                        onStart.Invoke();

                        var FileStrm = File.Open(file, FileMode.Open);
                                                
                        var result = Scanner.ScanFile(FileStrm);
                        FileStrm.Close();
                        
                        onCompleted?.Invoke(this, result);
                    }
                    else
                    {
                        Console.WriteLine("[Scanner.StartTask] ERROR FILE NOT EXISTS ");
                    }
                });
            }
            else
            {
                this.task = task;
            }
        }

        public void Run()
        {
            this.task.Start();
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
            ScanTasks.ScanMutex.WaitOne();

            if (FileStream.Length <= Configuration.MAX_FAST_SCAN_FILE)
            {
                ScanResult Result = new ScanResult(0, result.NotVirus);

                byte[] FileBuffer = new byte[Configuration.MAX_FAST_SCAN_FILE];
                int readed = FileStream.Read(FileBuffer, 0, FileBuffer.Length);

                if(readed == 0)
                {
                    ScanTasks.ScanMutex.ReleaseMutex();
                    return Result;
                }

                Array.Resize(ref FileBuffer, readed);

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

                            for(
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

                ScanTasks.ScanMutex.ReleaseMutex();
                return Result;
            }
            else
            {
                ScanTasks.ScanMutex.ReleaseMutex();
                return new ScanResult(0, result.NotVirus);
            }
        }
    }

    public static class ScanTasks
    {
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
        /// Запустить сколько возможно новых задач сканирования (всё упирается в лимит установленный конфигурацией)
        /// </summary>
        private static void UpdateActiveTasks()
        {
            ActiveScanTasks_Sync.WaitOne();

            while(TaskQueue.Count > 0 && ActiveScanTasks < Configuration.MAX_SCAN_TASKS)
            {
                TaskQueue.Dequeue().Run();
            }

            ActiveScanTasks_Sync.ReleaseMutex();
        }

        /// <summary>
        /// При старте сканирования
        /// </summary>
        private static void ScanStarted()
        {
            ActiveScanTasks_Sync.WaitOne();
            {
                ActiveScanTasks++;
                Console.WriteLine($"SCAN STARTED, active tasks {ActiveScanTasks}");
            }
            ActiveScanTasks_Sync.ReleaseMutex();
        }

        /// <summary>
        /// Событие окончания сканирования файла
        /// </summary>
        private static void ScanCompleted(ScanTask task, ScanResult result)
        {
            Console.WriteLine($"\n\n[SCAN COMPLETE EVENT] {task.file}, result {result.Result}");

            Connector.ToOutput(task.id, result);

            ActiveScanTasks_Sync.WaitOne();
            {
                ActiveScanTasks--;
            }
            ActiveScanTasks_Sync.ReleaseMutex();

            UpdateActiveTasks();
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

            UpdateActiveTasks();
            TaskQueue_Sync.ReleaseMutex();            
        }

        /// <summary>
        /// Инициализация сервиса
        /// </summary>
        public static void Init()
        {
            //qwerty
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