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

using Core.Kernel.ModuleLoader;
using Core.Kernel.ScanModule;
using Core.Kernel.Configuration;
using Core.Kernel.Quarantine;

namespace Core
{
    static class Initialization
    {
        static NamedPipeClientStream PartitionMon_CommandPipe = new NamedPipeClientStream("PartitionMon_Command");

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
        }
               
        /// <summary>
        /// Инициализация подключаемых(DLL) модулей
        /// </summary>
        static void initModules()
        {
            foreach (string FileName in Directory.GetFiles(Directory.GetCurrentDirectory() + "\\Modules\\", "*.dll"))
            {
#if DEBUG
                Console.WriteLine("[Kernel.initModules] Загрузка модуля -> " + FileName.Substring(FileName.LastIndexOf('\\') + 1, FileName.Length - FileName.LastIndexOf('\\') - 1));
#endif
                ModuleManager.Loader.LoadModule(FileName.Substring(FileName.LastIndexOf('\\') + 1, FileName.Length - FileName.LastIndexOf('\\') - 1));
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
        /// Инициализация подключений к модулям/компонентам
        /// </summary>
        static void initConnectModules()
        {
#if DEBUG
            Console.WriteLine("[Kernel.initConnectModules] Connect to PartitionMon_Command...");
#endif
            PartitionMon_CommandPipe.Connect();
        }




        /// <summary>
        /// Точка входа в ядро
        /// </summary>
        /// <param name="args"></param>
        static async Task Main(string[] args)
        {
            Console.CancelKeyPress += Console_CancelKeyPress;

            /*
            initKernelConfiguration();
            initKernelComponents();

            initModules();
            initConnectModules();
            */

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