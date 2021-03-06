﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Management;
using System.Linq;

using LoggerLib;



namespace MODULE__RESERVE_NEW_FILE_DETECTOR
{
    public static class Configuration
    {
        public static string API_MON_PIPE_NAME = "API_MON_FILTER";
        public static string COMMAND_PIPE_NAME = "PartitionMon.Command";
        public static bool RemovableAutoScan = false;

        //Флаг выключенной защиты
        public static bool Disable = false;

        public static Encoding NamedPipeEncoding = Encoding.Unicode;

        /// <summary>
        /// Какие файлы будут проверятся на флешке
        /// </summary>
        public static string[] RemovableDevicesFilter = new string[]{ "exe", "dll", "msi", "mp4"};
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



    /// <summary>
    /// Таблица носителей
    /// </summary>
    static class HardDrives
    {
        static public List<Drive> DriveTable = new List<Drive>(); //Таблица подключенных устройств
        static public List<string> WhiteSerialList = new List<string>(); //Белый лист USB накопителей, тут их сериальные номера, подгружаются с файла
        static public byte countConnectedRemovableDevices { get; set; } //Будет помогать определять, отключение/подключение устройств

        //Запись(строчка) в таблице
        public struct Drive
        {
            public DriveInfo DriveInf;
            public string VolumeLabel;
            public string SerialNumber;
            public long TotalSize;
            public long TotalFreeSpace;
            public string FileSystem;
            public bool IsConnected;
            public string RootDir;

            public Drive(DriveInfo drive)
            {
                this.DriveInf = drive;
                this.TotalSize = drive.TotalSize;
                this.TotalFreeSpace = drive.TotalFreeSpace;
                this.VolumeLabel = drive.VolumeLabel;
                this.FileSystem = drive.DriveFormat;
                this.RootDir = drive.RootDirectory.FullName;
                this.IsConnected = true;
                this.SerialNumber = null;
            }

            /// <summary>
            /// Проверка подключены ли эти устройства
            /// </summary>
            public bool CheckConnect(string[] SerialNumbers)
            {
                //Определить подключение, через WMI
                foreach (string serial in SerialNumbers)
                    if (serial == this.SerialNumber)
                    {
                        this.IsConnected = true;
                        return true;
                    }

                this.IsConnected = false;
                return false;
            }
        }

        /// <summary>
        /// Добавить в таблицу информацию о новом устройстве
        /// </summary>
        /// <returns>Количество устройств в таблице</returns>
        static public byte AddNewDrive(DriveInfo newDrive, string serialNumber)
        {
            Drive drive = new Drive(newDrive);
            drive.SerialNumber = serialNumber;

            DriveTable.Add(drive);
            return (byte)DriveTable.Count;
        }

        /// <summary>
        /// Есть ли устройство с таким серийником в таблице 
        /// </summary>
        static public bool CheckSerial(string serialNumber)
        {
            foreach (Drive mDrive in DriveTable)
            {
                if (serialNumber == mDrive.SerialNumber) return true;
            }

            return false;
        }

        /// <summary>
        /// Есть ли такое устройство в таблице
        /// </summary>
        static public bool CheckDrive(DriveInfo drive)
        {
            foreach (Drive drive1 in DriveTable)
            {
                if (drive1.VolumeLabel == drive.VolumeLabel &&
                   drive1.TotalSize == drive.TotalSize &&
                   drive1.FileSystem == drive.DriveFormat)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Получить информацию по сериал номеру
        /// </summary>
        static public Drive getDriveBySerial(string serialNumber)
        {
            foreach (Drive drive in DriveTable)
            {
                if (drive.SerialNumber == serialNumber)
                {
                    return drive;
                }
            }

            return DriveTable[0];
        }

        /// <summary>
        /// Проверить, принадлежит ли этому носителю такой сериал номер
        /// </summary>
        /// <returns>true, если сериал номер равен этому накопителю</returns>
        static public bool checkDriveSerial(DriveInfo drive, string serial)
        {
            foreach (Drive myDrive in DriveTable)
            {
                if (myDrive.FileSystem == drive.DriveFormat &&
                    myDrive.TotalSize == drive.TotalSize)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Обновление таблицы подключенных устройств
        /// </summary>
        static public void RefreshConnectedDevices(string[] serialNumbers)
        {
            //Всем ставить false (все устройства помечены как отключенные)
            for (int index = 0; index < DriveTable.Count; index++)
            {
                Drive newStruct = DriveTable[index];
                newStruct.IsConnected = false;
                DriveTable[index] = newStruct;
            }

            //А теперь проверка, какие из устройств в нашей таблице подключены
            for (int index = 0; index < DriveTable.Count; index++)
            {
                foreach (string serial in serialNumbers)
                {
                    //Проверка, есть ли устройство с таким серийником в нашей таблице
                    if (DriveTable[index].SerialNumber == serial)
                    {
                        //Если устройство с таким серийным номером есть в нашей таблице, то выставляем ему флаг CONNECTED
                        Drive newStruct = DriveTable[index];
                        newStruct.IsConnected = true;
                        DriveTable[index] = newStruct;

                        Connector.Logger.WriteLine($"[RemovableDevicesMon] Обновление таблицы, устройство SER:{serial} было подключено", LogLevel.OK);
                        break;
                    }
                }
            }
        }
    }


    static public class RemovableDeviceMonitor
    {
        static public Thread ThreadMonitor;

        static public void AddRemovableDeviceToScan(string pathToDrive)
        {
            Console.WriteLine(pathToDrive);
            List<FileInfo> files = new List<FileInfo>();

            foreach(FileInfo info in new DirectoryInfo(pathToDrive).GetFiles("*.exe"))
            {
                files.Add(info);
            }

            foreach (FileInfo info in new DirectoryInfo(pathToDrive).GetFiles("*.dll"))
            {
                files.Add(info);
            }

            foreach (FileInfo info in new DirectoryInfo(pathToDrive).GetFiles("*.mp4"))
            {
                files.Add(info);
            }


            foreach (FileInfo file in files)
            {
                Connector.Writer_Sync.WaitOne();
                {
                    Connector.FilterPipeWriter.Write("1" + file.FullName);
                    Connector.FilterPipeWriter.Flush();
                }
                Connector.Writer_Sync.ReleaseMutex();
            }

            Connector.Logger.WriteLine($"[FileSysApiMon.RemovableDeviceMonitor] Файлы({files.Count}) добавлены в очередь сканирования", LogLevel.INFO);
        }

        static private void Worker()
        {
            Connector.Logger.WriteLine("[FileSysApiMon.RemovableDeviceMonitor] Сервис мониторинга внешних носителей активен", LogLevel.OK);

            while (true)
            {
                ManagementObjectCollection collection = new ManagementObjectSearcher("SELECT * FROM Win32_usbhub WHERE Caption=\"Запоминающее устройство для USB\"").Get();
                string[] SerialNumbers = new string[collection.Count]; byte index = 0;
                foreach (ManagementObject obj in collection)
                {
                    //Выделение серийных номеров подключенных USB устройств
                    SerialNumbers[index] = obj["DeviceID"].ToString().Trim();
                    SerialNumbers[index] = SerialNumbers[index].Substring(SerialNumbers[index].LastIndexOf(@"\") + 1, (SerialNumbers[index].Length - SerialNumbers[index].LastIndexOf("\\")) - 1);
                }

                {
                    if (collection.Count != HardDrives.countConnectedRemovableDevices)
                    {
                        //Если в подключенных устройствах что то изменилось

                        if (collection.Count > HardDrives.countConnectedRemovableDevices)
                        {
                            //Новое ПОДКЛЮЧЕННОЕ устройство
                            Connector.Logger.WriteLine("[FileSysApiMon.RemovableDeviceMonitor] Обнаруженно подключение съемного устройства", LogLevel.WARN);

                            foreach (string serialNumber in SerialNumbers)
                            {
                                if (!HardDrives.CheckSerial(serialNumber))
                                {
                                    //Если устройство с таким серийным номером отсутствует в таблице
                                    Connector.Logger.WriteLine($"[FileSysApiMon.RemovableDeviceMonitor] Устройство ранее не подключалось SER:{serialNumber}, ожидание 3000ms", LogLevel.WARN);
                                    Thread.Sleep(3000); //Даем винде время подумать
                                    DriveInfo[] ConnectedDrives = DriveInfo.GetDrives();

                                    //Выделение этого носителя, среди массива DriveInfo
                                    foreach (DriveInfo drive in ConnectedDrives)
                                    {
                                        if (!drive.IsReady || drive.DriveType != DriveType.Removable)
                                        {
                                            continue;
                                        }

                                        if (!HardDrives.CheckDrive(drive))
                                        {
                                            //Если устройство с такими данными(серийник не проверяется) не существует в таблице
                                            byte countDevices = HardDrives.AddNewDrive(drive, serialNumber);
                                            Connector.Logger.WriteLine($"[FileSysApiMon.RemovableDeviceMonitor] Устройство добавлено в таблицу SER:{serialNumber} TOTAL_SIZE:{drive.TotalSize} FILESYS:{drive.DriveFormat}, колво устройств в таблицe {countDevices}", LogLevel.WARN);

                                            if (Configuration.RemovableAutoScan)
                                            {
                                                new Task(() =>
                                                {
                                                    int probes = 0;

                                                    while (probes++ < 10)
                                                    {
                                                        Connector.Logger.WriteLine($"[FileSysApiMon.RemovableDeviceMonitor] Проба сканировать({probes})", LogLevel.WARN);

                                                        if (drive.IsReady)
                                                        {
                                                            Thread.Sleep(200);
                                                            try
                                                            {
                                                                AddRemovableDeviceToScan(drive.Name);
                                                            }
                                                            catch
                                                            {
                                                                continue;
                                                            }

                                                            break;
                                                        }

                                                        Thread.Sleep(500);
                                                    }

                                                }).Start();
                                            }
                                        }
                                        else
                                        {
                                            //Если устройство с таким серийником отсутствует в таблице, но существует с такими данными
                                            Connector.Logger.WriteLine("[FileSysApiMon.RemovableDeviceMonitor] Устройство с таким серийником отсутствует в таблице, но существует с такими данными", LogLevel.ERROR);
                                        }
                                    }
                                }
                                else
                                {
                                    //Если в таблице есть устройство с таким серийником, то сравниваем сейчас его новые данные с теми, которые есть у нас в таблице
                                    Connector.Logger.WriteLine($"[FileSysApiMon.RemovableDeviceMonitor] Устройство с таким серийным номером SER:{serialNumber}, ранее уже подключалось", LogLevel.INFO);
                                    HardDrives.Drive DriveInfoFromTable = HardDrives.getDriveBySerial(serialNumber);
                                    Thread.Sleep(2000); //Хз почему, но винде нужно дать время подумать
                                    DriveInfo[] ConnectedDrives = DriveInfo.GetDrives();

                                    foreach (DriveInfo drive in ConnectedDrives)
                                    {
                                        //Выделение этого носителя, среди массива DriveInfo
                                        if (drive.IsReady && !HardDrives.checkDriveSerial(drive, serialNumber)) continue;

                                        if (Configuration.RemovableAutoScan)
                                        {
                                            new Task(() =>
                                            {
                                                int probes = 0;

                                                while (probes++ < 10)
                                                {
                                                    Connector.Logger.WriteLine($"[FileSysApiMon.RemovableDeviceMonitor] Проба сканировать({probes})", LogLevel.WARN);

                                                    if (drive.IsReady)
                                                    {
                                                        Thread.Sleep(200);
                                                        try
                                                        {
                                                            AddRemovableDeviceToScan(drive.Name);
                                                        }
                                                        catch
                                                        {
                                                            continue;
                                                        }

                                                        break;
                                                    }

                                                    Thread.Sleep(500);
                                                }

                                            }).Start();
                                        }

                                        if (drive.IsReady && DriveInfoFromTable.TotalFreeSpace != drive.TotalFreeSpace)
                                        {
                                            Connector.Logger.WriteLine($"[FileSysApiMon.RemovableDeviceMonitor] {drive.Name} Съемное устройство было изменено на другом устройстве, требуется перепроверка файлов", LogLevel.WARN);
                                            try
                                            {
                                                if (Configuration.RemovableAutoScan) AddRemovableDeviceToScan(drive.Name);
                                            }
                                            catch (Exception ex)
                                            {
                                                Connector.Logger.WriteLine(ex.Message, LogLevel.ERROR);
                                            }
                                            //Если свободное место во время предыдущего подключения
                                            // не совпадает с свободным местом при текущем подключении, значит там что то изменилось
                                        }
                                        else
                                        {
                                            Connector.Logger.WriteLine("[FileSysApiMon.RemovableDeviceMonitor] Эта флешка не изменялась на других устройствах", LogLevel.WARN);
                                        }
                                    }

                                }
                            }
                        }

                        if (collection.Count < HardDrives.countConnectedRemovableDevices)
                        {
                            Connector.Logger.WriteLine("[FileSysApiMon.RemovableDeviceMonitor] Обнаруженно отключение съемного устройства", LogLevel.WARN);
                            HardDrives.RefreshConnectedDevices(SerialNumbers);
                        }

                        HardDrives.countConnectedRemovableDevices = (byte)collection.Count;
                    }

                }


                Thread.Sleep(500);
            }
        }

        static public void ClearAllDevices()
        {
            HardDrives.DriveTable.Clear();
        }

        static public void Init()
        {
            ThreadMonitor = new Thread(Worker)
            {
                Priority = ThreadPriority.Lowest,
                Name = "RemovableDeviceMonitor"
            };

            ThreadMonitor.Start();
            Thread.Sleep(100);
        }

        static public void StopService()
        {
            ThreadMonitor.Abort();
        }
    }


    /*========*/









    public static class PartitionMonitor
    {
        private static readonly Thread CommandExecuter = new Thread(CommandThread);

        private static FileSystemWatcher[] FileSystemWatchers = new FileSystemWatcher[0];
        private static readonly Mutex FileSystemWatchers_sync = new Mutex();

        public static List<string> CreatedFilesBuffer = new List<string>();
        private static readonly Mutex CreatedFilesBuffer_sync = new Mutex();

        public static Queue<string> FileQueue = new Queue<string>();

        public static Thread LoaderThread = new Thread(Loader) { Name = "MonitorLoader" };
        public static Thread BufferCleaner = new Thread(Cleaner) { Name = "MonitorBufferCleaner" };


        private static bool RemoveIfExists(string path)
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

        public static void Cleaner()
        {
            while (true)
            {
                Connector.Logger.WriteLine($"[FileSysApiMon.AutoCleaner] Очистка буффера файлов {CreatedFilesBuffer.Count}");
                CreatedFilesBuffer.Clear();
                Thread.Sleep(TimeSpan.FromSeconds(60));
            }
        }

        public static void Loader()
        {
            while (true)
            {
                if(FileQueue.Count > 0)
                {
                    var file = FileQueue.Dequeue();

                    if (Configuration.Disable)
                    {
                        continue;
                    }

                    if (RemoveIfExists(file))
                    {
                        continue;
                    }
                    else
                    {
                        CreatedFilesBuffer.Add(file);
                    }


                    Connector.FilterPipeWriter.Write("1" + file);
                }
                Thread.Sleep(10);
            }
        }

        public static void CommandThread()
        {
            Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Wait connection...");
            {
                Connector.CommandPipe.WaitForConnection();
                Connector.CommandReader = new BinaryReader(Connector.CommandPipe, Configuration.NamedPipeEncoding);
            }
            Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Connected", LogLevel.OK);


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
                        // 0 - Создать монитор
                        case '0':
                            {
                                if (args[1].Length == 0)
                                {
                                    args[1] = "*.*";
                                }

                                CreatePartitionMon(args[0], args[1]);                                
                                break;
                            }

                        // 1 - Создать монитор
                        case '1':
                            {
                                DisablePartitionMon(args[0]);
                                break;
                            }

                        // 2 - Включить авто проверку съемных носителей
                        case '2':
                            {
                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Включаю автоскан съемных носителей");

                                Configuration.RemovableAutoScan = true;
                                break;
                            }

                        // 3 - Выключить авто проверку съемных носителей
                        case '3':
                            {
                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Выключаю автоскан съемных носителей");

                                Configuration.RemovableAutoScan = false;
                                break;
                            }

                        // 4 - Очистить информацию о подключенных устройствах
                        case '4':
                            {
                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Очищаю информацию о подключенных устройствах");

                                RemovableDeviceMonitor.ClearAllDevices();
                                break;
                            }

                        // 5 - Приостановить защиту
                        case '5':
                            {
                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Защита отключена!", LogLevel.WARN);

                                Configuration.Disable = true;
                                break;
                            }

                        // 6 - Активировать защиту
                        case '6':
                            {
                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Защита включена!", LogLevel.OK);

                                Configuration.Disable = false;
                                break;
                            }

                        // 7 - Выключить всё
                        case '7':
                            {
                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Отключаю всё!", LogLevel.OK);

                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Отключаю монитор съемных носителей!", LogLevel.OK);
                                RemovableDeviceMonitor.ThreadMonitor.Abort();

                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Поток-загрузчик!", LogLevel.OK);
                                LoaderThread.Abort();

                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Чищу все записи!", LogLevel.OK);
                                RemovableDeviceMonitor.ClearAllDevices();

                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Отключаю входную трубу!", LogLevel.OK);
                                Connector.FilterInputPipe.Close();

                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Отключаю командную трубу!", LogLevel.OK);
                                Connector.CommandPipe.Close();


                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Остановка потока загрузчика!", LogLevel.OK);
                                LoaderThread.Abort();


                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Остановка потока очистки буффера!", LogLevel.OK);
                                BufferCleaner.Abort();

                                foreach (FileSystemWatcher watcher in FileSystemWatchers)
                                {
                                    Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Отключаю монитор раздела!", LogLevel.OK);
                                    watcher.Dispose();
                                }

                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Отключаю командный поток!", LogLevel.OK);
                                CommandExecuter.Abort();
                                break;
                            }

                        default:
                            {
                                Connector.Logger.WriteLine("[FileSysApiMon.CommandThread] Command not found", LogLevel.WARN);
                                break;
                            }
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

            Connector.Logger.WriteLine($"[FileSysApiMon.CreatePartition] Created api monitor for {PartitionPath}", LogLevel.OK);
        }

        /// <summary>
        /// Отключить монитор раздела
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
            FileQueue.Enqueue(e.FullPath);
        }

        static void ChangedFileEvent(object sender, FileSystemEventArgs e)
        {
            FileQueue.Enqueue(e.FullPath);
        }


        static void Error(object sender, ErrorEventArgs e)
        {
            Connector.Logger.WriteLine($"[FileSysApiMon.Error] =============", LogLevel.ERROR);
            Connector.Logger.WriteLine($"[FileSysApiMon.Error] ERROR {e}", LogLevel.ERROR);
            Connector.Logger.WriteLine($"[FileSysApiMon.Error] =============", LogLevel.ERROR);
        }

        /// <summary>
        /// Запуск потока обработки команд и обработки фильтрации
        /// </summary>
        public static void Init()
        {
            Connector.FilterInputPipe.Connect();
            Connector.FilterPipeWriter = new BinaryWriter(Connector.FilterInputPipe, Configuration.NamedPipeEncoding);

            CommandExecuter.Start();
        }

        /// <summary>
        /// Отключение всех потоков и мониторов файловой системы
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
                PartitionMonitor.LoaderThread.Start();
                PartitionMonitor.BufferCleaner.Start();
                Connector.Init();
                PartitionMonitor.Init();
                RemovableDeviceMonitor.Init();
            }).Start();
            return 0;
        }

        public static void Stop()
        {
            PartitionMonitor.StopAll();
        }
    }
}
