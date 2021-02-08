/*
    Наименование модуля: Core
    Описание модуля
        С этого модуля начинается работа всего средства, модуль запускает остальные модули
        и служит связующим звеном для всех модулей.
 */

using System;

using System.IO;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Threading.Tasks;

using Core.Kernel.Configurations;
using Core.Kernel.VirusesManager;
using Core.Kernel.Cryptographer;
using Core.Kernel.ModuleLoader;
using Core.Kernel.ScanModule;
using Core.Kernel.Quarantine;
using Core.Kernel.Connectors;
using Core.Kernel.API;

namespace Core
{
    static class KernelInitializator
    {
#if DEBUG
        private static Process LoggerProc;
        private static Process GUI_Proc;
#endif

        public static Configuration Config;


        /// <summary>
        /// Инициализация конфигурации ядра
        /// </summary>
        static void InitKernelConfiguration()
        {
            Config = new Configuration("SystemConf.xml", "UserConf.xml");
        }

        /// <summary>
        /// Инициализация внутренних компонентов ядра
        /// ВАЖНО! Менеджер обнаруженных вирусов должен быть запущен раньше чем менеджер задач сканирования
        /// </summary>
        static void InitKernelComponents()
        {
            API.Init();

            ScannerResponseHandler.Init();
            FoundVirusesManager.Init();
            ScanTasks.Init();
            Quarantine.InitStorage();
        }

        /// <summary>
        /// Инициализация подключаемых(DLL) модулей
        /// </summary>
        static void InitModules()
        {
            foreach (string FileName in Directory.GetFiles(Directory.GetCurrentDirectory() + "\\Modules\\", "*.dll"))
            {
                string File = FileName.Substring(FileName.LastIndexOf('\\') + 1, FileName.Length - FileName.LastIndexOf('\\') - 1);
#if DEBUG
                KernelConnectors.Logger.WriteLine("[Kernel.initModules] Загрузка модуля -> " + File);
#endif
                ModuleManager.Loader.LoadModule(File);
            }

#if DEBUG
            KernelConnectors.Logger.WriteLine("[Kernel.initModules] Проверка таблицы сервисов");
            foreach (ModuleManager.Module m in ModuleManager.Modules)
            {
                KernelConnectors.Logger.WriteLine($"[Kernel.initModules] Модуль {m.ModuleName}, статус модуля {m.IsRunning}");
            }
#endif
        }


        /// <summary>
        /// Применить базовые настройки модулей
        /// </summary>
        private static void ApplyingBasicSettings()
        {
            //Partition monitor
            new Task(() =>
            {
                var drives = DriveInfo.GetDrives();
                var SystemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System));

                for (byte index = 0; index < drives.Length; index++)
                {
                    KernelConnectors.Logger.WriteLine($"[Kernel.ApplyingBasicSettings] Found drive {drives[index].Name}");

                    if (drives[index].DriveType == DriveType.Removable || 
                        drives[index].DriveType == DriveType.CDRom ||
                        drives[index].DriveType == DriveType.Network ||
                        drives[index].DriveType == DriveType.Unknown ||
                        drives[index].Name == SystemDrive)
                    {
                        //Если диск не подходит
                        continue;
                    }

                    KernelConnectors.Logger.WriteLine($"[Kernel.ApplyingBasicSettings] Create api mon for {drives[index].Name}");
                    KernelConnectors.PartitionMon_CommandWriter.Write($"0*{drives[index].Name}&*.*");
                    KernelConnectors.PartitionMon_CommandWriter.Flush();
                    KernelConnectors.Logger.WriteLine($"[Kernel.ApplyingBasicSettings] Create api mon WRITED");
                }
            }).Start();


            //VirusesDb 
            new Task(() =>
            {
                //Выгрузить все сигнатуры в менеджер сканера
                KernelConnectors.VirusesDb_CommandWriter.Write("/upload_to_scanner");
                KernelConnectors.VirusesDb_CommandWriter.Flush(); 
            }).Start();
        }


        /// <summary>
        /// Точка входа в ядро
        /// </summary>
        /// <param name="args"></param>
        static async Task Main(string[] args)
        {
            Console.CancelKeyPress += Console_CancelKeyPress;
            AppDomain.CurrentDomain.ProcessExit += OnCloseProcess;

#if DEBUG
            LoggerProc = Process.Start("Loggers\\Logger.exe");
            KernelConnectors.Logger.Init();
#endif

            //Инициализация конфигурации ядра
            InitKernelConfiguration();

            //Инициализация DLL модулей (ввод их в состояние готовности подключится к ядру)
            InitModules();

            //Инициализация входящих подключений
            KernelConnectors.InitInputConnections();

            //Инициализация исходящих подключений
            KernelConnectors.InitOutputConnections();

            //Инициализация компонентов ядра
            InitKernelComponents();

            //Базовая настройка модулей
            ApplyingBasicSettings();

            if (Config.GUI_Autostart)
            {
                KernelConnectors.Logger.WriteLine("[Kernel] Запуск GUI");

                if(File.Exists("GUI\\GUI.exe"))
                    GUI_Proc = Process.Start("GUI\\GUI.exe");
            }

            await Task.Delay(-1);
        }

        private static void OnCloseProcess(object sender, EventArgs e)
        {
#if DEBUG
            if (!LoggerProc.HasExited)
            {
                LoggerProc.Kill();
            }
#endif
        }

        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
#if DEBUG
            if (!LoggerProc.HasExited)
            {
                LoggerProc.Kill();
            }
#endif
        }



    }
}