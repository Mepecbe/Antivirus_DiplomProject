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

    static class Initialization
    {
        static void Main(string[] args)
        {
            //Старт загрузчика
            {
                //Запуск модулей
                foreach(string FileName in Directory.GetFiles(Directory.GetCurrentDirectory() + "\\Modules\\", "*.dll"))
                {
                    Console.WriteLine(FileName);

                    Assembly asm = Assembly.LoadFrom(FileName);

                    string ModuleFileName = FileName.Substring(FileName.LastIndexOf('\\') + 1);
                    Type t = asm.GetType(ModuleFileName.Substring(0,ModuleFileName.Length-3) + "Initializator", true, true);

                    MethodInfo method = t.GetMethod("EntryPoint");

                    if (method == null)
                    {
                        Console.WriteLine("===\nТОЧКА ВХОДА В НЕ НАЙДЕНА\n===");
                    }
                    else
                    {
                        Console.WriteLine("Вызов метода EntryPoint");
                        object result = method.Invoke(null, new object[] { });
                        Console.WriteLine(result);
                    }
                }
            }

            //ScanQueue.receiveThread.Start();
        }
    }
}