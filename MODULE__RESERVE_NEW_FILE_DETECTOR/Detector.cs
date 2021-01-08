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
    public static class PartitionMonitor
    {
        private static Thread CommandExecuter = new Thread(CommandThread);

        private static FileSystemWatcher[] FileSystemWatchers = new FileSystemWatcher[0];
        private static Encoding NamedPipeEncoding = Encoding.Unicode;
        private static object locker = new object();

        /// <summary>
        /// Для отправки путей к файлам, которые были обнаружены
        /// </summary>
        private static NamedPipeClientStream ClientStream = new NamedPipeClientStream("PartitionMon_FilePaths");

        /// <summary>
        /// Для приёма команд
        /// </summary>
        private static NamedPipeServerStream CommandStream = new NamedPipeServerStream("PartitionMon_Command");

        /// <summary>
        /// Для чтения команд
        /// </summary>
        private static StreamReader CommandReader;

        /// <summary>
        /// Для записи путей обнаруженных файлов
        /// </summary>
        private static StreamWriter Writer;

        public static Task Runner = new Task(() =>
        {
            {
#if DEBUG
                Console.WriteLine("[PartitionMonitor] [Task.Runner] Wait for connection PartitionMon_Command...");
#endif

                CommandStream.WaitForConnection();
                CommandReader = new StreamReader(CommandStream, NamedPipeEncoding);

#if DEBUG
                Console.WriteLine($"[FileDetector] [Task.Runner] CommandStream connected");
#endif

                CommandExecuter.Start();
            }

            {
#if DEBUG
                Console.WriteLine($"[FileDetector] Wait connect to PartitionMon_FilePaths");
#endif
                ClientStream.Connect();
                Writer = new StreamWriter(ClientStream, NamedPipeEncoding) { AutoFlush = true };

#if DEBUG
                Console.WriteLine($"[FileDetector] Connected to PartitionMon_FilePaths");
#endif
            }

        });

        public static void CommandThread()
        {
            while (true)
            {
#if DEBUG
                Console.WriteLine("[FileDetector] [CommandThread] Wait command...");
#endif
                string buffer = CommandReader.ReadLine();
#if DEBUG
                Console.WriteLine("[FileDetector] [CommandThread] Read command ->" + buffer);
#endif

                if (buffer.Length > 0)
                {
                    //Парсинг операндов
                    string op1 = string.Empty,
                           op2 = string.Empty;

                    try
                    {
                        op1 = buffer.Substring(buffer.IndexOf('*') + 1, buffer.IndexOf('&') - 2);
                        op2 = buffer.Substring(buffer.IndexOf('&') + 1);
                    }
                    catch
                    {
#if DEBUG
                        Console.WriteLine($"[FileDetector] [CommandThread] Parameter parsing error(receive command ->{buffer}<-)");
#endif
                        continue;
                    }
#if DEBUG
                    Console.WriteLine($"[FileDetector] [CommandThread] ({buffer}) parsed =>>> op1 and op2 = \"{op1}\" and \"{op2}\" ");
#endif

                    switch (buffer[0])
                    {
                        //command id 0 - Create Partition Monitor
                        case '0':
                            {
                                if (op2.Length <= 1) op2 = "*.*";
#if DEBUG
                                Console.WriteLine($"[FileDetector] Create Partition monitor for \"{op1}\", used filter \"{op2}\"");
#endif
                                CreatePartitionMon(op1, op2);
                                break;
                            }

                        //command id 1 - Disable partition monitor 
                        case '1':
                            {
#if DEBUG
                                Console.WriteLine($"[FileDetector] Create Partition monitor for \"{op1}\", used filter \"{op2}\"");
#endif
                                DisablePartitionMon(op1);
                                break;
                            }

#if DEBUG
                        default:
                            {
                                Console.WriteLine("[FileDetector] [CommandThread] Command not found");
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
            Console.WriteLine( $"[FileDetector] [CommandThread] (DisablePartitionMon) Remove monitor for \"{PartitionPath}\"");
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
                            Console.WriteLine($"[FileDetector] [CommandThread] (DisablePartitionMon) SUCCESS Remove monitor for \"{PartitionPath}\" ");
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
            Console.WriteLine($"[FileDetector] [ChangedFileEvent] Detected changed file {e.Name}");
#endif
            Writer.WriteLine((int)e.ChangeType + e.FullPath);
        }

        /// <summary>
        /// Disable all threads and FileSys watchers
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
            PartitionMonitor.Runner.Start();
            return 0;
        }

        public static void Stop()
        {
            PartitionMonitor.StopAll();
            System.GC.Collect();
        }
    }
}
