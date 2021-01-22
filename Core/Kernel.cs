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

using Core;
using Core.Kernel.ModuleLoader;
using Core.Kernel.ScanModule;
using Core.Kernel.Configuration;
using Core.Kernel.Quarantine;
using Core.Kernel.Connectors;
using Core.Kernel.API;

namespace Core
{
    static class Initialization
    {
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
            ScannerResponseHandler.Init();
            FilterHandler.Run();
            ScanTasks.Init();
            FoundVirusesManager.Init();
            Quarantine.InitStorage();

            API.Init();
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
                Console.WriteLine("[Kernel.initModules] Загрузка модуля -> " + File);
#endif
                ModuleManager.Loader.LoadModule(File);
            }

#if DEBUG
            Console.WriteLine("[Kernel.initModules] Проверка таблицы сервисов");
            foreach (ModuleManager.Module m in ModuleManager.Modules)
            {
                Console.WriteLine($"[Kernel.initModules] Модуль {m.ModuleName}, статус модуля {m.IsRunning}");
            }
#endif
        }



        /// <summary>
        /// Точка входа в ядро
        /// </summary>
        /// <param name="args"></param>
        static async Task Main(string[] args)
        {
            Console.CancelKeyPress += Console_CancelKeyPress;

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




#if DEBUG
            {
                Thread.Sleep(2000);
                Console.WriteLine("Состояние подключения трубы команд вирусной БД " + KernelConnectors.VirusesDb_CommandPipe.IsConnected);
                Console.WriteLine("Состояние подключения трубы команд монитора разделов(API) " + KernelConnectors.PartitionMon_CommandPipe.IsConnected);

                Console.WriteLine("Состояние подключения фильтра " + KernelConnectors.Filter_Input.IsConnected);

                Console.WriteLine("Состояние подключения входной трубы сканнера " + KernelConnectors.ScannerService_Input.IsConnected);
                Console.WriteLine("Состояние подключения выходной трубы сканнера " + KernelConnectors.ScannerService_Output.IsConnected);
            }
#endif

            testMethods();
            await Task.Delay(-1);
        }

        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("Shutdown");
        }




        private static void testMethods()
        {
            /*Quarantine.InitStorage();
            Console.WriteLine(Quarantine.AddFileToStorage(@"D:\123.txt").fileName);
            */


            
            new Task(() =>
            {
                Thread.Sleep(3000);
                var command = @"0*D:\&*.*";
                byte[] commandd = Configuration.NamedPipeEncoding.GetBytes(command);
                var cmd = new StreamWriter(KernelConnectors.PartitionMon_CommandPipe, Configuration.NamedPipeEncoding) { AutoFlush = true };

                Console.WriteLine($"(TASK) SEND '{command}'");
                cmd.WriteLine(command);
                Console.WriteLine("(TASK) END");
            }).Start();

            /*
            new Task(() =>
            {
                Thread.Sleep(3000);
                Console.WriteLine("ScanTasks add");

                foreach(string file in Directory.GetFiles("D:\\testFiles"))
                {
                    ScanTasks.Add(file);
                }
            }).Start();



            new Task(() =>
            {
                Thread.Sleep(8000);
                {
                    Console.WriteLine("\n\nFOUND VIRUSES RECORDS");
                    //ScanTasks.Add("D:\\office1.pdf");

                    foreach (VirusInfo virus in FoundVirusesManager.VirusesTable)
                    {
                        Console.WriteLine($"VIRUS {virus.id}, {virus.file}");
                        Console.WriteLine("move to quarantine");
                        var result = Quarantine.AddFileToStorage(virus.file);

                        if (result.is_success)
                        {
                            Console.WriteLine("  success");
                        }
                    }

                    Console.WriteLine("Count tasks");
                    Console.WriteLine(ScanTasks.tasks.Count);

                    if (Quarantine.AddFileToStorage("D:\\testFiles\\office1.pdf").is_success)
                    {
                        Console.WriteLine("MOVED TO QUARANTINE");
                    }
                }
            }).Start();


            new Task(() =>
            {
                Thread.Sleep(10000);
                {
                    string[] files = Quarantine.GetAllFiles();

                    Console.WriteLine("ALL FILES IN QUARANTINE");
                    foreach(string file in files)
                    {
                        Console.WriteLine(file);
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

                    Console.WriteLine($"(TASK) SEND '{command}'");
                    cmd.WriteLine(command);
                    Console.WriteLine($"(TASK) END");
                }).Start();*/
            }
    }
}