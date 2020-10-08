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

namespace Core
{
    /// <summary>
    /// Класс, который реализует очереди сканирования
    /// Служит промежутком между сервисом сканирования файлов и модулем связи с драйверами и модулем диспетчера съемных носителей  
    /// </summary>
    static class ScanQueue
    {
        //По этой трубе происходит приём имен файлов от модуля связи с драйвером / резервным модулем отслеживания
        public static NamedPipeServerStream serverStream = new NamedPipeServerStream("FileNamePipe");

        public static Thread receiveThread = new Thread(() =>
        {
            serverStream.WaitForConnection();
        });
    }

    static class Loader
    {
        public static List<Module> Modules = new List<Module>();

        public class Module
        {
            public readonly string ModuleName;
            public readonly Assembly ModuleAssembly;
            private bool Running;
            public bool IsRunning { get { return this.Running; } }

            public Module(string ModuleFileName)
            {
                this.Running = false;
                this.ModuleName = ModuleFileName;
                this.ModuleAssembly = Assembly.LoadFrom("Modules\\" + ModuleFileName);

                {
                    //Проверка существования класса инициализатора
                    bool found = false;
                    foreach (Type type in this.ModuleAssembly.GetTypes())
                    {
                        if (type.Name == "Initializator")
                        {
                            found = true;
                            break;
                        }
                    }

                    if (!found)
                    {
                        //Не найден класс инициализатора
                        return;
                    }
                }

                //Вход в модуль
                Type InitializatorType = this.ModuleAssembly.GetType(ModuleFileName.Substring(0, ModuleFileName.Length - 3) + "Initializator", true, true);
                MethodInfo EntryPoint = InitializatorType.GetMethod("EntryPoint");

                if (EntryPoint == null)
                {
                    return;
                }
                else
                {
                    object result = EntryPoint.Invoke(null, new object[] { });

                    if ((byte)result == 0)
                    {
                        this.Running = true;
                    }
                }
            }
        }

        public static void LoadModule(string ModuleFileName)
        {
            Modules.Add(new Module(ModuleFileName));
        }
    }

    static class Initialization
    {
        static void Main(string[] args)
        {
            Console.CancelKeyPress += Console_CancelKeyPress;

            //Точка входа в антивирус

            {
                //Запуск модулей
                foreach (string FileName in Directory.GetFiles(Directory.GetCurrentDirectory() + "\\Modules\\", "*.dll"))
                {
                    Loader.LoadModule(FileName.Substring(FileName.LastIndexOf('\\') + 1, FileName.Length - FileName.LastIndexOf('\\') - 1));
                }

                Console.WriteLine("Проверка таблицы сервисов");
                foreach (Loader.Module m in Loader.Modules)
                {
                    Console.WriteLine($"Модуль {m.ModuleName}, статус модуля {m.IsRunning}");
                }
            }
        }

        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("cancel");
        }
    }
}