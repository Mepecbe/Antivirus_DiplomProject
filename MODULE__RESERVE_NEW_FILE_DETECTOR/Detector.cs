using System;
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
        const string PipeName = "FileNamePipe";

        public static Thread CommandExecuter = new Thread(CommandThread);
        private static NamedPipeClientStream ClientStream = new NamedPipeClientStream(PipeName);
        private static Task[] PartitionMonitors = new Task[0];

        public static void CommandThread()
        {
#if DEBUG
            Debugger.StartDebug();
            Debugger.WriteLog($"[FileDetector] Ожидание подключения к трубе \"{PipeName}\"");
#endif

            ClientStream.Connect();

#if DEBUG
            Debugger.WriteLog("[FileDetector] Подключен к серверу");
#endif
            while (true)
            {
                byte[] buffer = new byte[512];
                if(ClientStream.Read(buffer, 0, 512) > 0)
                {
                    string command = Encoding.Unicode.GetString(buffer);
#if DEBUG
                    Debugger.WriteLog("[CommandThread] " + command);
#endif
                    
                    switch (command[0])
                    {
                        case '0': {
#if DEBUG
                                Debugger.WriteLog("[CommandThread] Create Partition mon");
#endif

                                ClientStream.Write(Encoding.Unicode.GetBytes("Hello world"), 0, 11);
                                break; 
                            }

                        case '1':
                            {
#if DEBUG
                                Debugger.WriteLog("[CommandThread] Stop Partition mon");
#endif
                                break;
                            }


                    }
                }

            }
        }



        public static void PartitionMon()
        {

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
