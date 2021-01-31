/*
    Наименование модуля: Core(Ядро)
    Описание модуля
        С этого модуля начинается работа всего средства, модуль запускает остальные модули
        и служит связующим звеном для всех модулей. Содержит в себе потоки 
 */

using System;

using System.IO;
using System.IO.Pipes;

using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.Collections.Generic;
using System.Security.Cryptography;

using System.Reflection;
using System.Runtime.CompilerServices;

using System.IO.IsolatedStorage;

using System.Diagnostics;

using Core;
using Core.Kernel.ModuleLoader;
using Core.Kernel.ScanModule;
using Core.Kernel.Configuration;
using Core.Kernel.Quarantine;
using Core.Kernel.Connectors;
using Core.Kernel.API;

using LoggerLib;
using System.Windows;

namespace Core
{
    static class Initialization
    {
#if DEBUG
        private static Process LoggerProc;
#endif


        /// <summary>
        /// Инициализация конфигурации ядра
        /// </summary>
        static void InitKernelConfiguration()
        {
#warning "сделать подгрузку из файла"
            Configuration.NamedPipeEncoding = Encoding.Unicode;
        }

        /// <summary>
        /// Инициализация внутренних компонентов ядра
        /// </summary>
        static void InitKernelComponents()
        {
            API.Init();

            ScannerResponseHandler.Init();
            FilterHandler.Run();
            ScanTasks.Init();
            FoundVirusesManager.Init();
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
        /// Точка входа в ядро
        /// </summary>
        /// <param name="args"></param>
        static async Task Main(string[] args)
        {
            //Console.CancelKeyPress += Console_CancelKeyPress;
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

            testMethods();
            await Task.Delay(-1);
        }

        private static void OnCloseProcess(object sender, EventArgs e)
        {
            Console.WriteLine("CLOSEEEE");
            KernelConnectors.Logger.WriteLine("Shutdown");

#if DEBUG
            if (!LoggerProc.HasExited)
            {
                LoggerProc.Kill();
            }
#endif
        }

        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            KernelConnectors.Logger.WriteLine("Shutdown");

#if DEBUG
            if (!LoggerProc.HasExited)
            {
                LoggerProc.Kill();
            }
#endif
        }




        private static void testMethods()
        {
            /*
                Quarantine.InitStorage();
                KernelConnectors.Logger.WriteLine(Quarantine.AddFileToStorage(@"D:\123.txt").fileName);
            */


            /*
            new Task(() =>
            {
                Thread.Sleep(3000);
                var command = @"0*D:\&*.*";
                byte[] commandd = Configuration.NamedPipeEncoding.GetBytes(command);
                var cmd = new StreamWriter(KernelConnectors.PartitionMon_CommandPipe, Configuration.NamedPipeEncoding) { AutoFlush = true };

                KernelConnectors.Logger.WriteLine($"(TASK) SEND '{command}'");
                cmd.WriteLine(command);
                KernelConnectors.Logger.WriteLine("(TASK) END");
            }).Start();*/


            new Task(() =>
            {
                Thread.Sleep(5000);

                foreach (string file in Directory.GetFiles(@"C:\Users\Cisco\Desktop\karise\dist", "*.*", SearchOption.AllDirectories))
                {
                    ScanTasks.Add(file);
                }

            });//.Start();


            /*
            new Task(() =>
            {
                Thread.Sleep(3000);
                KernelConnectors.Logger.WriteLine("ScanTasks add");

                foreach(string file in Directory.GetFiles("D:\\testFiles"))
                {
                    ScanTasks.Add(file);
                }
            }).Start();



            new Task(() =>
            {
                Thread.Sleep(8000);
                {
                    KernelConnectors.Logger.WriteLine("\n\nFOUND VIRUSES RECORDS");
                    //ScanTasks.Add("D:\\office1.pdf");

                    foreach (VirusInfo virus in FoundVirusesManager.VirusesTable)
                    {
                        KernelConnectors.Logger.WriteLine($"VIRUS {virus.id}, {virus.file}");
                        KernelConnectors.Logger.WriteLine("move to quarantine");
                        var result = Quarantine.AddFileToStorage(virus.file);

                        if (result.is_success)
                        {
                            KernelConnectors.Logger.WriteLine("  success");
                        }
                    }

                    KernelConnectors.Logger.WriteLine("Count tasks");
                    KernelConnectors.Logger.WriteLine(ScanTasks.tasks.Count);

                    if (Quarantine.AddFileToStorage("D:\\testFiles\\office1.pdf").is_success)
                    {
                        KernelConnectors.Logger.WriteLine("MOVED TO QUARANTINE");
                    }
                }
            }).Start();


            new Task(() =>
            {
                Thread.Sleep(10000);
                {
                    string[] files = Quarantine.GetAllFiles();

                    KernelConnectors.Logger.WriteLine("ALL FILES IN QUARANTINE");
                    foreach(string file in files)
                    {
                        KernelConnectors.Logger.WriteLine(file);
                    }
                }
            }).Start();*/

                /*
                new Task(() =>
                {
                    Thread.Sleep(12000);
                    var command = @"1*C:\&*";
                    byte[] commandd = Configuration.NamedPipeEncoding.GetBytes(command);
                    var cmd = new StreamWriter(PartitionMon_CommandPipe, Configuration.NamedPipeEncoding) { AutoFlush = true };

                    KernelConnectors.Logger.WriteLine($"(TASK) SEND '{command}'");
                    cmd.WriteLine(command);
                    KernelConnectors.Logger.WriteLine($"(TASK) END");
                }).Start();*/
            }
    }
}