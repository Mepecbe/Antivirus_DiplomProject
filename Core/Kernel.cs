﻿/*
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

using Core.Kernel.ModuleLoader;
using Core.Kernel.ScanModule;
using Core.Kernel.Configuration;
using Core.Kernel.Quarantine;
using Core.Kernel.Connectors;

namespace Core
{
    static class Initialization
    {
        /// <summary>
        /// Инициализация конфигурации ядра
        /// </summary>
        static void initKernelConfiguration()
        {
#warning "сделать подгрузку из файла"
            Configuration.NamedPipeEncoding = Encoding.Unicode;
        }

        /// <summary>
        /// Инициализация внутренних компонентов ядра
        /// </summary>
        static void initKernelComponents()
        {
            FileQueue.Run();
            Quarantine.InitStorage();
        }
               
        /// <summary>
        /// Инициализация подключаемых(DLL) модулей
        /// </summary>
        static void initModules()
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
            initKernelConfiguration();

            //Инициализация компонентов ядра
            initKernelComponents();

            //Инициализация входящих подключений
            Connectors.InitInputConnections();

            //Инициализация исходящих подключений
            Connectors.InitOutputConnections();

            //Инициализация DLL модулей
            initModules();

#if DEBUG
            {
                Thread.Sleep(5000);
                Console.WriteLine("Состояние подключения трубы команд вирусной БД " + Connectors.VirusesDb_CommandPipe.IsConnected);
                Console.WriteLine("Состояние подключения трубы команд монитора разделов(API) " + Connectors.PartitionMon_CommandPipe.IsConnected);

                Console.WriteLine("Состояние подключения фильтра " + Connectors.Filter_Input.IsConnected);

                Console.WriteLine("Состояние подключения входной трубы сканнера " + Connectors.ScannerService_Input.IsConnected);
                Console.WriteLine("Состояние подключения выходной трубы сканнера " + Connectors.ScannerService_Output.IsConnected);
            }
#endif

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


            /*
            new Task(() =>
            {
                Thread.Sleep(7000);
                var command = @"0*C:\&*.*";
                byte[] commandd = Configuration.NamedPipeEncoding.GetBytes(command);
                var cmd = new StreamWriter(PartitionMon_CommandPipe, Configuration.NamedPipeEncoding) { AutoFlush = true };

                Console.WriteLine($"(TASK) SEND '{command}'");
                cmd.WriteLine(command);
                Console.WriteLine("(TASK) END");
            }).Start();

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