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
        private static Task[] PartitionMonitors = new Task[0];
        public static Thread CommandExecuter = new Thread(CommandThread);
        private static FileSystemWatcher[] FileSystemWatchers = new FileSystemWatcher[0];
        
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
                    string op1 = string.Empty, op2 = string.Empty;
                    
                    try
                    {
                        op1 = buffer.Substring(buffer.IndexOf('*') + 1, buffer.Length - buffer.IndexOf('&') - 1);
                        op2 = buffer.Substring(buffer.IndexOf('&') + 1);
                    }
                    catch
                    {
#if DEBUG
                        Debugger.WriteLog($"[FileDetector] [CommandThread] Error parse operands");
#endif
                        continue;
                    }
#if DEBUG
                    Debugger.WriteLog($"[FileDetector] [CommandThread] op1 and op2 = \"{op1}\" and \"{op2}\" ");
#endif

                    switch (buffer[0])
                    {
                        case '0': 
                            {
                                //Создание монитора раздела
                                CreatePartitionMon(op1, op2);
                                break; 
                            }

                        case '1':
                            {
                                //Отключение монитора раздела
                                break;
                            }


                    }
                }

            }
        }



        public static void CreatePartitionMon(string PartitionPath, string Filter)
        {
#if DEBUG
            Debugger.WriteLog($"[FileDetector] Create Partition monitor for \"{PartitionPath}\", used filter \"{Filter}\"");
#endif

            FileSystemWatcher systemWatcher = new FileSystemWatcher(PartitionPath, Filter);

            systemWatcher.Created += CreateFileEvent;
            systemWatcher.Changed += ChangedFileEvent;
            systemWatcher.EnableRaisingEvents = true;
            
            Array.Resize(ref FileSystemWatchers, FileSystemWatchers.Length + 1);

            FileSystemWatchers[FileSystemWatchers.Length - 1] = systemWatcher;
        }

        static void CreateFileEvent(object sender, FileSystemEventArgs e)
        {
#if DEBUG
            Debugger.WriteLog($"[FileDetector] [CreateFileEvent] Detected create file {e.Name}");
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
    }

    public static class Initializator
    {
        public static byte EntryPoint()
        {
            PartitionMonitor.CommandExecuter.Start();
            return 0;
        }
    }
}
