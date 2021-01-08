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

using Core.Kernel_MODULES.ModuleLoader;
using Core.Kernel_MODULES.ScanModule;
using Core.Kernel_MODULES.Configuration;

namespace Core
{
    static class Initialization
    {
        static NamedPipeClientStream PartitionMon_CommandPipe = new NamedPipeClientStream("PartitionMon_Command");

        /// <summary>
        /// Инициализация подключений к модулям/компонентам
        /// </summary>
        static void initConnectModules()
        {
#if DEBUG
            Console.WriteLine("[Kernel] Connect to PartitionMon_Command...");
#endif
            PartitionMon_CommandPipe.Connect();



            new Task(() =>
            {
                Thread.Sleep(2000);
                Console.WriteLine("(TASK) SEND");
                var command = @"0*C:\&*.*";
                byte[] commandd = Configuration.NamedPipeEncoding.GetBytes(command);

                PartitionMon_CommandPipe.Write(commandd, 11, commandd.Length);
                Console.WriteLine("(TASK) END");
            }).Start();

        }

        /// <summary>
        /// Инициализация внутренних компонентов ядра
        /// </summary>
        static void initKernelComponents()
        {
            FileQueue.RunAPIMonitorPipe();
        }





















        /// <summary>
        /// Точка входа в ядро
        /// </summary>
        /// <param name="args"></param>
        static async Task Main(string[] args)
        {
            Console.CancelKeyPress += Console_CancelKeyPress;

            ModuleManager.Loader.LoadModule("MODULE_SCAN.dll");

            
            {
                //Запуск модулей
                foreach (string FileName in Directory.GetFiles(Directory.GetCurrentDirectory() + "\\Modules\\", "*.dll"))
                {
#if DEBUG
                    Console.WriteLine("Загрузка модуля -> " + FileName.Substring(FileName.LastIndexOf('\\') + 1, FileName.Length - FileName.LastIndexOf('\\') - 1));
#endif
                    ModuleManager.Loader.LoadModule(FileName.Substring(FileName.LastIndexOf('\\') + 1, FileName.Length - FileName.LastIndexOf('\\') - 1));
                }

#if DEBUG
                Console.WriteLine("Проверка таблицы сервисов");
                foreach (ModuleManager.Module m in ModuleManager.Modules)
                {
                    Console.WriteLine($"Модуль {m.ModuleName}, статус модуля {m.IsRunning}");
                }
#endif
            }

            initKernelComponents();
            initConnectModules();

            await Task.Delay(-1);
        }

        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("Shutdown");
        }
    }
}