using System;
using System.Collections;
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
using MODULE__SCAN.Yara;

namespace MODULE__SCAN
{
    public static class Configuration
    {
        public static Encoding PipeEncoding = Encoding.Unicode;
        public static bool UsingYara = true;

        /// <summary>
        /// Максимальный размер файла для быстрого сканирования (файл подходящий под такой критерий будет полностью считываться в память)
        /// </summary>
        public const int MAX_FAST_SCAN_FILE = 1_000_000_000;

        public const int THREAD_COUNT = 40;

        /// <summary>
        /// Максимальное количество задач сканирования
        /// </summary>
        public const int MAX_SCAN_TASKS = THREAD_COUNT * 2;

        public const int SCAN_THREAD_SLEEP = 100;

        public const string YaraRulesDir = @"Modules\YARA\Rules";
        public const SearchOption YaraRulesSearchOption = SearchOption.TopDirectoryOnly;
    }


    public static class Connector
    {
        public static NamedPipeServerStream commandPipe = new NamedPipeServerStream("Scanner.CommandPipe");
        public static NamedPipeServerStream inputPipe = new NamedPipeServerStream("ScannerService.input");
        public static NamedPipeServerStream signaturesPipe = new NamedPipeServerStream("ScannerService.signatures");

        public static NamedPipeClientStream outputPipe = new NamedPipeClientStream("ScannerService.output");

        private static Thread inputHandler = new Thread(inputThread)         { Name = "inputHandler" };
        private static Thread signatureHandler = new Thread(signatureThread) { Name = "signatureHandler" };
        private static Thread commandHandler = new Thread(commandThread)     { Name = "commandHandler" };

        private static BinaryWriter outputWriter;
        private static BinaryReader commandReader;

        public static LoggerClient Logger = new LoggerClient("Logger.Modules.Scanner", "Log");

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
            Logger.WriteLine("[Scanner.inputThread] ScannerService.input ожидание подключения");

            inputPipe.WaitForConnection();
            var binaryReader = new BinaryReader(inputPipe, Configuration.PipeEncoding);

            Logger.WriteLine("[Scanner.inputThread] ScannerService.input подключен");

            while (true)
            {
                int id = 0;

                try
                {
                    id = binaryReader.ReadInt32();
                }
                catch
                {
                    Logger.WriteLine("[Scanner.signatureThread] Отключаю поток", LogLevel.ERROR);
                    break;
                }

                string file = binaryReader.ReadString();

                Logger.WriteLine($"[Scanner.inputThread] Добавляю задачу сканирования, айди {id}, путь -> {file}");
                ScanTasks.Add(id, file);
            }
        }

        public static void signatureThread()
        {
            Logger.WriteLine("[Scanner.signatureThread] Ожидание подключения");

            signaturesPipe.WaitForConnection();
            var binaryReader = new BinaryReader(signaturesPipe);

            Logger.WriteLine("[Scanner.signatureThread] ScannerService.signatures подключен", LogLevel.OK);

            while (true)
            {
                var ID = 0;

                try
                {
                    ID = binaryReader.ReadInt16();
                }
                catch
                {
                    Logger.WriteLine("[Scanner.signatureThread] Отключаю поток", LogLevel.ERROR);
                    break;
                }

                var Signature = binaryReader.ReadBytes(binaryReader.ReadInt16());

                if (ID >= Scanner.Signatures.Length)
                {
                    Logger.WriteLine("[Scanner.signatureThread] Записываю сигнатуру в локальный буфер");

                    Array.Resize(ref Scanner.Signatures, Scanner.Signatures.Length + 1);
                    Scanner.Signatures[Scanner.Signatures.Length - 1] = new Signature(Signature);
                }
                else
                {
                    Logger.WriteLine("[Scanner.signatureThread] Обновление сигнатуры в локальном буффере");

                    Scanner.Signatures[ID] = new Signature(Signature);
                }
            }
        }

        public static void commandThread()
        {
            Logger.WriteLine("[Scanner.commandThread] Ожидание подключения", LogLevel.WARN);
            commandPipe.WaitForConnection();
            commandReader = new BinaryReader(commandPipe, Configuration.PipeEncoding);
            Logger.WriteLine("[Scanner.commandThread] Подключено", LogLevel.OK);

            while (true) 
            {
                var code = commandReader.ReadByte();

                switch (code)
                {
                    case 0:
                        {
                            Logger.WriteLine("[Scanner.commandThread] Очистка буфера задач сканирования", LogLevel.WARN);

                            {
                                ScanTasks.TaskQueue.Clear();
                                ScanTasks.ActiveScanTasks = 0;
                            }

                            break;
                        }

                    case 1:
                        {
                            Logger.WriteLine("[Scanner.commandThread] Очистка буфера задач сканирования", LogLevel.WARN);

                            {
                                ScanTasks.TaskQueue.Clear();
                                ScanTasks.ActiveScanTasks = 0;
                            }

                            for(int index = 0; index < ScanTasks.ScanThreads.Length; index++)
                            {
                                Logger.WriteLine($"[Scanner.commandThread] Остановка потока сканирования {index}", LogLevel.WARN);
                                ScanTasks.ScanThreads[index].Abort();
                            }

                            Logger.WriteLine("[Scanner.commandThread] Остановка потоков", LogLevel.WARN);
                            inputHandler.Abort();
                            signatureHandler.Abort();

                            Thread.Sleep(100);

                            Logger.WriteLine("[Scanner.commandThread] Закрытие труб", LogLevel.WARN);
                            commandPipe.Close();
                            inputPipe.Close();
                            commandPipe.Close();
                            outputPipe.Close();

                            commandHandler.Abort();
                            break;
                        }
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

            Logger.WriteLine("[Scanner.Init] Ожидание подключения к outputPipe", LogLevel.WARN);

            outputPipe.Connect();
            outputWriter = new BinaryWriter(outputPipe);

            Logger.WriteLine("[Scanner.Init] outputPipe подключен", LogLevel.OK);

            commandHandler.Start();
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

                int readed = 0;

                try
                {
                    readed = FileStream.Read(FileBuffer, 0, FileBuffer.Length);
                }
                catch(Exception ex)
                {
                    Connector.Logger.WriteLine($"[Scanner] Ошибка чтения файла {ex.Message}", LogLevel.ERROR);
                    return new ScanResult(0, result.Error);
                }

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
                    Connector.Logger.WriteLine($"[Scanner] Ошибка во время проверки {ex.Message}", LogLevel.ERROR);
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
        public static Thread[] ScanThreads = new Thread[Configuration.THREAD_COUNT];

        /// <summary>
        /// Очередь задач сканирования
        /// </summary>
        public static Queue TaskQueue = new Queue();

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
            TaskQueue.Enqueue(new ScanTask(id, pathToFile, ScanStarted, ScanCompleted));
        }

        public static void ScanThread()
        {
            while (true)
            {
                lock(TaskQueue.SyncRoot)
                {
                    if (TaskQueue.Count > 0)
                    {
                        var task = (ScanTask)TaskQueue.Dequeue();

                        {
                            if (Configuration.UsingYara)
                            {
                                try
                                {
                                    Connector.Logger.WriteLine($"[ScanThread {Thread.CurrentThread.Name}] Поток начал проверку правил Yara", LogLevel.WARN);
                                    var result = YaraIntegration.CheckFile(task.file);

                                    ScanCompleted(
                                        task, 
                                        new ScanResult(0, result ? MODULE__SCAN.result.Virus : MODULE__SCAN.result.NotVirus)
                                    );                                  
                                }
                                catch(Exception ex)
                                {
                                    Connector.Logger.WriteLine($"[ScanThread {Thread.CurrentThread.Name}] Ошибка при проверке правил\n{ex.Message}", LogLevel.ERROR);
                                    ScanCompleted(
                                        task,
                                        new ScanResult(0, MODULE__SCAN.result.Error)
                                    ); ;
                                }
                            }
                            else
                            {
                                FileStream stream = null;

                                try
                                {
                                    stream = File.Open(task.file, FileMode.Open, FileAccess.Read);
                                }
                                catch (PathTooLongException)
                                {
                                    Connector.Logger.WriteLine($"[SCANNER] PathTooLongException", LogLevel.ERROR);
                                    ScanCompleted(task, new ScanResult(0, MODULE__SCAN.result.NotVirus));
                                }
                                catch (UnauthorizedAccessException)
                                {
                                    Connector.Logger.WriteLine($"[SCANNER] UnauthorizedAccessException", LogLevel.ERROR);
                                    ScanCompleted(task, new ScanResult(0, MODULE__SCAN.result.NotVirus));
                                }
                                catch (DirectoryNotFoundException)
                                {
                                    Connector.Logger.WriteLine($"[SCANNER] DirectoryNotFoundException", LogLevel.ERROR);
                                    ScanCompleted(task, new ScanResult(0, MODULE__SCAN.result.NotVirus));
                                }
                                catch (FileNotFoundException)
                                {
                                    Connector.Logger.WriteLine($"[SCANNER] FileNotFoundException", LogLevel.ERROR);
                                    ScanCompleted(task, new ScanResult(0, MODULE__SCAN.result.NotVirus));
                                }
                                catch (Exception ex)
                                {
                                    Connector.Logger.WriteLine($"[SCANNER] ERROR OPEN FILE {ex.Message}", LogLevel.ERROR);
                                    ScanCompleted(task, new ScanResult(0, MODULE__SCAN.result.Error));
                                    continue;
                                }

                                Connector.Logger.WriteLine($"[ScanThread {Thread.CurrentThread.Name}] Поток начал сканирование поиском сигнатуры", LogLevel.WARN);

                                var result = Scanner.ScanFile(stream);

                                stream.Close();
                                ScanCompleted(task, result);
                            }
                        }

                        continue;
                    }
                }

                Thread.Sleep(Configuration.SCAN_THREAD_SLEEP);
            }
        }

        /// <summary>
        /// Инициализация сервиса
        /// </summary>
        public static void Init()
        {
            for (int index = 0; index < ScanThreads.Length; index++)
            {
                ScanThreads[index] = new Thread(ScanThread) { Name = "Scan Thread " + index.ToString() };
                ScanThreads[index].Start();
            }
        }
    }

    public static class Initializator
    {
        public static byte EntryPoint()
        {
            new Thread(() => Connector.Init()).Start();
            ScanTasks.Init();
            YaraIntegration.Init();

            return 0;
        }

        public static void Exit()
        {

        }
    }
}