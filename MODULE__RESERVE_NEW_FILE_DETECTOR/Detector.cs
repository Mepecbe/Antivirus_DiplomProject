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

    public static class ReserveDetector
    {
        public static Thread CommandExecuter = new Thread(CommandThread);
        private static FileSystemWatcher[] FileSystemWatchers = new FileSystemWatcher[0];
        private static NamedPipeClientStream ClientStream = new NamedPipeClientStream("FileNamePipe");
        private static StreamReader PipeReader;
        private static Task[] PartitionMonitors = new Task[0];

        public static void CommandThread()
        {
#if DEBUG
            Debugger.StartDebug();
            Debugger.WriteLog(Debugger.LogLevel.Warning, $"[FileDetector] Ожидание подключения к трубе FileNamePipe"); 
#endif

            ClientStream.Connect();
            PipeReader = new StreamReader(ClientStream);

#if DEBUG
            Debugger.WriteLog(Debugger.LogLevel.Warning, "[FileDetector] Подключен к ядру");
#endif
            while (true)
            {
#if DEBUG
                Debugger.WriteLog("[FileDetector] [CommandThread] Read...");
#endif
                string buffer = PipeReader.ReadLine();
#if DEBUG
                Debugger.WriteLog("[FileDetector] [CommandThread] Readed");
#endif


                if (buffer.Length > 0)
                {
                    string op1 = buffer.Substring(buffer.IndexOf('*')+1, buffer.Length - buffer.IndexOf('&')-1);
                    string op2 = buffer.Substring(buffer.IndexOf('&')+1);

#if DEBUG
                    Debugger.WriteLog("[FileDetector] [CommandThread] " + buffer);
                    Debugger.WriteLog($"[FileDetector] [CommandThread] op1 and op2 = \"{op1}\" and \"{op2}\" ");
#endif

                    switch (buffer[0])
                    {
                        case '0': 
                            {
                                CreatePartitionMon(op1, op2);
                                break; 
                            }

                        case '1':
                            {
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
        }

        static void ChangedFileEvent(object sender, FileSystemEventArgs e)
        {
#if DEBUG
            Debugger.WriteLog($"[FileDetector] [ChangedFileEvent] Detected changed file {e.Name}");
#endif
        }
    }

    public static class Initializator
    {
        public static byte EntryPoint()
        {
            ReserveDetector.CommandExecuter.Start();
            return 0;
        }
    }
}
