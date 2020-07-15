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
        //dll библиотеки модулей в которых необходимо вызвать функцию EntryPoint
        static readonly string[] moduleNames  = new string[] {
            "MODULE__DRIVER_CONNECTOR.dll", 
            "MODULE__FILTER.dll",
            "MODULE__RESERVE_NEW_FILE_DETECTOR.dll",
            "MODULE__SCANNER_SERVICE.dll"
        };

        static void Main(string[] args)
        {
            //Первый операнд - название именованной трубы, по которому будет производится соединение 
            //  с внешней программой

            /* ПРОВЕРКА КОНТРОЛЬНОЙ СУММЫ ФАЙЛОВ(ЦЕЛОСТНОСТЬ ФАЙЛОВ МОДУЛЕЙ)*/

            /* КОНЕЦ ПРОВЕРКИ*/

            {
                Assembly asm = Assembly.LoadFrom(moduleNames[0]);

                Console.WriteLine("Типы");
                foreach (Type a in asm.GetTypes()) Console.WriteLine(a);
                //return; 

                Type t = asm.GetType("MODULE_DRIVERCONNECTOR.Initializator", true, true);
                Type[] type = asm.GetTypes();
                                
                object obj = Activator.CreateInstance(t);

                MethodInfo method = t.GetMethod("EntryPoint");

                // вызываем метод, передаем ему значения для параметров и получаем результат
                object result = method.Invoke(null, new object[] { });
                Console.WriteLine(result);
            }

            //ScanQueue.receiveThread.Start();
        }
    }
}

/*
 * При запуске проверить контрольную сумму файлов с теми, что на сервере
 * Драйвер запрещает всяческие операции над файлами сторонним приложениям
 */
