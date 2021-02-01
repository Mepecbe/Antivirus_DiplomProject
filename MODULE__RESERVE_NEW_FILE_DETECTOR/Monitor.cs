using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using LoggerLib;



namespace MODULE__RESERVE_NEW_FILE_DETECTOR
{
    public static class Configuration
    {
        public static string API_MON_PIPE_NAME = "API_MON_FILTER";
        public static string COMMAND_PIPE_NAME = "PartitionMon.Command";

        public static Encoding NamedPipeEncoding = Encoding.Unicode;
    }

    public static class Connector
    {
        /// <summary>
        /// Для отправки путей к файлам в модуль фильтра, которые были обнаружены
        /// </summary>
        public static NamedPipeClientStream FilterInputPipe = new NamedPipeClientStream(Configuration.API_MON_PIPE_NAME);

        /// <summary>
        /// Для приёма команд
        /// </summary>
        public static NamedPipeServerStream CommandPipe = new NamedPipeServerStream(Configuration.COMMAND_PIPE_NAME);

        /// <summary>
        /// Для чтения команд
        /// </summary>
        public static BinaryReader CommandReader;

        /// <summary>
        /// Для записи путей обнаруженных файлов
        /// </summary>
        public static BinaryWriter FilterPipeWriter;

        public static Mutex Writer_Sync = new Mutex();

        public static LoggerClient Logger = new LoggerClient("Logger.ApiMonitor", "Api monitor");

        public static void Init()
        {
#if DEBUG
            Logger.Init();
#endif
        }
    }

    public static class PartitionMonitor
    {
        private static readonly Thread CommandExecuter = new Thread(CommandThread);

        private static FileSystemWatcher[] FileSystemWatchers = new FileSystemWatcher[0];
        private static readonly Mutex FileSystemWatchers_sync = new Mutex();

        public static List<string> CreatedFilesBuffer = new List<string>();
        private static readonly Mutex CreatedFilesBuffer_sync = new Mutex();

        private static bool Exists(string path)
        {
            for (int index = 0; index < CreatedFilesBuffer.Count; index++)
            {
                if (CreatedFilesBuffer[index] == path)
                {
                    CreatedFilesBuffer.RemoveAt(index);
                    return true;
                }
            }

            return false;
        }


        public static void CommandThread()
        {
            Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Wait connection...");
            {
                Connector.CommandPipe.WaitForConnection();
                Connector.CommandReader = new BinaryReader(Connector.CommandPipe, Configuration.NamedPipeEncoding);
            }
            Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Connected");


            while (true)
            {
                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Wait command...");

                string buffer = Connector.CommandReader.ReadString();

                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Read command ->" + buffer);

                if (buffer.Length > 0)
                {
                    //Парсинг операндов
                    string[] args = buffer.Substring(buffer.IndexOf('*')+1).Split('&');
                    
                    switch (buffer[buffer.IndexOf('*') - 1])
                    {
                        //command id 0 - Create Partition Monitor
                        case '0':
                            {
                                if (args[1].Length == 0)
                                {
                                    args[1] = "*.*";
                                }

                                CreatePartitionMon(args[0], args[1]);                                
                                break;
                            }

                        //command id 1 - Disable partition monitor 
                        case '1':
                            {
                                DisablePartitionMon(args[0]);
                                break;
                            }

#if DEBUG
                        default:
                            {
                                Console.WriteLine("[FileSysApiMon.CommandThread] Command not found");
                                break;
                            }
#endif
                    }
                }

            }
        }


        /// <summary>
        /// Создать и включить FileSystemWatcher для раздела
        /// </summary>
        public static void CreatePartitionMon(string PartitionPath, string Filter)
        {
            FileSystemWatchers_sync.WaitOne();
            {
                Array.Resize(ref FileSystemWatchers, FileSystemWatchers.Length + 1);

                FileSystemWatchers[FileSystemWatchers.Length - 1] = new FileSystemWatcher(PartitionPath, Filter);

                FileSystemWatchers[FileSystemWatchers.Length - 1].NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.CreationTime;
                FileSystemWatchers[FileSystemWatchers.Length - 1].IncludeSubdirectories = true;

                FileSystemWatchers[FileSystemWatchers.Length - 1].Created += CreateFileEvent;
                FileSystemWatchers[FileSystemWatchers.Length - 1].Changed += ChangedFileEvent;
                FileSystemWatchers[FileSystemWatchers.Length - 1].Error   += Error;

                FileSystemWatchers[FileSystemWatchers.Length - 1].EnableRaisingEvents = true;
            }
            FileSystemWatchers_sync.ReleaseMutex();

            Connector.Logger.WriteLine($"[FileSysApiMon.CreatePartition] Created api monitor for {PartitionPath}", LogLevel.WARN);
        }

        /// <summary>
        /// Disable FileSystemWatcher for partition
        /// </summary>
        /// <param name="PartitionPath"></param>
        public static void DisablePartitionMon(string PartitionPath)
        {
            lock (FileSystemWatchers_sync)
            {
                for (int index = 0; index < FileSystemWatchers.Length; index++)
                {
                    if (FileSystemWatchers[index].Path == PartitionPath)
                    {
                        {
                            FileSystemWatchers[index].Dispose();
                            FileSystemWatchers[index] = FileSystemWatchers[FileSystemWatchers.Length - 1];
                            Array.Resize(ref FileSystemWatchers, FileSystemWatchers.Length - 1);
                        }
                    }
                }
            }
        }

        static void CreateFileEvent(object sender, FileSystemEventArgs e)
        {
            Connector.Logger.WriteLine($"[FileSysApiMon.CreateFileEvent] CREATE EVENT", LogLevel.WARN);

            Connector.Writer_Sync.WaitOne();
            {
                CreatedFilesBuffer_sync.WaitOne();
                {
                    CreatedFilesBuffer.Add(e.FullPath);
                }
                CreatedFilesBuffer_sync.ReleaseMutex();

                Connector.FilterPipeWriter.Write((int)e.ChangeType + e.FullPath);
                Connector.FilterPipeWriter.Flush();
            }
            Connector.Writer_Sync.ReleaseMutex();
        }


        static void ChangedFileEvent(object sender, FileSystemEventArgs e)
        {
            Connector.Logger.WriteLine($"[FileSysApiMon.ChangedFileEvent] EDIT EVENT", LogLevel.WARN);

            Connector.Writer_Sync.WaitOne();
            {
                CreatedFilesBuffer_sync.WaitOne();
                {
                    if (Exists(e.FullPath))
                    {
                        Connector.Logger.WriteLine($"[FileSysApiMon.ChangedFileEvent] EDIT, EXISTS {e.FullPath}", LogLevel.WARN);

                        CreatedFilesBuffer_sync.ReleaseMutex();
                        return;
                    }
                }
                CreatedFilesBuffer_sync.ReleaseMutex();

                Connector.FilterPipeWriter.Write((int)e.ChangeType + e.FullPath);
                Connector.FilterPipeWriter.Flush();
            }
            Connector.Writer_Sync.ReleaseMutex();
        }


        static void Error(object sender, ErrorEventArgs e){
            Connector.Logger.WriteLine($"[FileSysApiMon.Error] ERROR {e}", LogLevel.ERROR);
        }


    public static void Init()
        {
            Connector.FilterInputPipe.Connect();
            Connector.FilterPipeWriter = new BinaryWriter(Connector.FilterInputPipe, Configuration.NamedPipeEncoding);

            CommandExecuter.Start();
        }

        /// <summary>
        /// Disable all threads and FileSys watchers
        /// </summary>
        public static void StopAll()
        {
            CommandExecuter.Abort();

            Connector.FilterInputPipe.Close();
            Connector.CommandPipe.Close();

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
            new Task(() =>
            {
                Connector.Init();
                PartitionMonitor.Init();
            }).Start();
            return 0;
        }

        public static void Stop()
        {
            PartitionMonitor.StopAll();
        }
    }
}
