using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;


namespace MODULE__RESERVE_NEW_FILE_DETECTOR
{
#if DEBUG
    public static class Debugger
    {
        private static NamedPipeClientStream DebugStream = new NamedPipeClientStream("Antivirus_Dbg");
        private static StreamWriter DebugWriter;

        public static void StartDebug()
        {
            DebugStream.Connect();
            DebugWriter = new StreamWriter(DebugStream, Encoding.Unicode) { AutoFlush = true };
            DebugWriter.WriteLine($"MODULE__RESERVE_NEW_FILE_DETECTOR debug started at {DateTime.Now}");
        }

        public enum LogLevel
        {
            Info,
            Warning,
            Error
        }

        public static void WriteLog(string message)
        {
            //Info
            DebugWriter.WriteLine('0' + message);
        }

        public static void WriteLog(LogLevel level, string message)
        {
            DebugWriter.WriteLine((byte)level + message);
        }
    }
#endif

    public static class PartitionMonitor
    {
        public static Thread CommandExecuter = new Thread(CommandThread);

        private static FileSystemWatcher[] FileSystemWatchers = new FileSystemWatcher[0];
        private static object locker = new object();

        private static NamedPipeClientStream ClientStream = new NamedPipeClientStream("PartitionMon_FilePaths");
        private static NamedPipeServerStream CommandStream = new NamedPipeServerStream("PartitionMon_Command");

        private static StreamReader CommandReader; //Для чтения команд
        private static StreamWriter Writer; //Для отправки путей к файлам

        public static void CommandThread()
        {
#if DEBUG
            Debugger.StartDebug();
            Debugger.WriteLog(Debugger.LogLevel.Warning, $"[FileDetector] Wait connection to pipe PartitionMon_FilePaths");
#endif

            ClientStream.Connect();
            Writer = new StreamWriter(ClientStream, Encoding.Unicode) { AutoFlush = true };

#if DEBUG
            Debugger.WriteLog(Debugger.LogLevel.Info, $"[FileDetector] Connected to PartitionMon_FilePaths");
            Debugger.WriteLog(Debugger.LogLevel.Warning, $"[FileDetector] Create command pipe and wait client connection");
#endif

            CommandStream.WaitForConnection();
            CommandReader = new StreamReader(CommandStream, Encoding.Unicode);

#if DEBUG
            Debugger.WriteLog(Debugger.LogLevel.Info, "[FileDetector] Connected to PartitionMon_FilePaths");
#endif
            while (true)
            {
#if DEBUG
                Debugger.WriteLog("[FileDetector] [CommandThread] Wait command...");
#endif
                string buffer = CommandReader.ReadLine();
#if DEBUG
                Debugger.WriteLog("[FileDetector] [CommandThread] Read command");
#endif


                if (buffer.Length > 0)
                {
                    //Парсинг операндов
                    string op1 = string.Empty,
                           op2 = string.Empty;

                    try
                    {
                        Console.WriteLine("Try parse op1 ");
                        op1 = buffer.Substring(buffer.IndexOf('*') + 1, buffer.IndexOf('&') - 2);
                        op2 = buffer.Substring(buffer.IndexOf('&') + 1);
                    }
                    catch
                    {
#if DEBUG
                        Debugger.WriteLog($"[FileDetector] [CommandThread] Parameter parsing error(receive command ->{buffer}<-)");
#endif
                        continue;
                    }
#if DEBUG
                    Debugger.WriteLog($"[FileDetector] [CommandThread] ({buffer}) parsed =>>> op1 and op2 = \"{op1}\" and \"{op2}\" ");
#endif

                    switch (buffer[0])
                    {
                        //command id 0 - Create Partition Monitor
                        case '0':
                            {
                                if (op2.Length <= 1) op2 = "*.*";
#if DEBUG
                                Debugger.WriteLog($"[FileDetector] Create Partition monitor for \"{op1}\", used filter \"{op2}\"");
#endif
                                CreatePartitionMon(op1, op2);
                                break;
                            }

                        //command id 1 - Disable partition monitor 
                        case '1':
                            {
#if DEBUG
                                Debugger.WriteLog($"[FileDetector] Create Partition monitor for \"{op1}\", used filter \"{op2}\"");
#endif
                                DisablePartitionMon(op1);
                                break;
                            }

#if DEBUG
                        default:
                            {
                                Debugger.WriteLog("[FileDetector] [CommandThread] Command not found");
                                break;
                            }
#endif
                    }
                }

            }
        }

        /// <summary>
        /// Create and enable FileSystemWatcher for partition
        /// </summary>
        /// <param name="PartitionPath"></param>
        /// <param name="Filter"></param>
        public static void CreatePartitionMon(string PartitionPath, string Filter)
        {
            lock (locker)
            {
                Array.Resize(ref FileSystemWatchers, FileSystemWatchers.Length + 1);
                FileSystemWatchers[FileSystemWatchers.Length - 1] = new FileSystemWatcher(PartitionPath, Filter);

                FileSystemWatchers[FileSystemWatchers.Length - 1].Created += CreateFileEvent;
                FileSystemWatchers[FileSystemWatchers.Length - 1].Changed += ChangedFileEvent;
                FileSystemWatchers[FileSystemWatchers.Length - 1].IncludeSubdirectories = true;
                FileSystemWatchers[FileSystemWatchers.Length - 1].EnableRaisingEvents = true;
            }
        }

        /// <summary>
        /// Disable FileSystemWatcher for partition
        /// </summary>
        /// <param name="PartitionPath"></param>
        public static void DisablePartitionMon(string PartitionPath)
        {
#if DEBUG
            Debugger.WriteLog(Debugger.LogLevel.Warning, $"[FileDetector] [CommandThread] (DisablePartitionMon) Remove monitor for \"{PartitionPath}\"");
#endif
            lock (locker)
            {
                for (int index = 0; index < FileSystemWatchers.Length; index++)
                {
                    if (FileSystemWatchers[index].Path == PartitionPath)
                    {
                        {
                            FileSystemWatchers[index].Dispose();
                            FileSystemWatchers[index] = FileSystemWatchers[FileSystemWatchers.Length - 1];
                            Array.Resize(ref FileSystemWatchers, FileSystemWatchers.Length - 1);
#if DEBUG
                            Debugger.WriteLog(Debugger.LogLevel.Info, $"[FileDetector] [CommandThread] (DisablePartitionMon) SUCCESS Remove monitor for \"{PartitionPath}\" ");
#endif
                        }
                    }
                }
            }
        }

        static void CreateFileEvent(object sender, FileSystemEventArgs e)
        {
#if DEBUG
            Writer.WriteLine($"[FileDetector] [CreateFileEvent] Detected create file {e.Name}");
#endif
            Writer.WriteLine((int)e.ChangeType + e.FullPath);
        }

        static void ChangedFileEvent(object sender, FileSystemEventArgs e)
        {
#if DEBUG
            Debugger.WriteLog($"[FileDetector] [ChangedFileEvent] Detected changed file {e.Name}");
#endif
            Writer.WriteLine((int)e.ChangeType + e.FullPath);
        }

        /// <summary>
        /// Disable all threads and FIleSys watchers
        /// </summary>
        public static void StopAll()
        {
            CommandExecuter.Abort();
            ClientStream.Close();
            CommandStream.Close();

            foreach (FileSystemWatcher watcher in FileSystemWatchers)
            {
                watcher.Dispose();
            }
        }
    }

    public static class Initializator
    {
        public static byte EntryPoint()
        {
            PartitionMonitor.CommandExecuter.Start();
            return 0;
        }

        public static void Stop()
        {
            PartitionMonitor.StopAll();
        }
    }
}
