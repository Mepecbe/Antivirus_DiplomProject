using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Reflection;
using System.IO.Pipes;
using System.Threading;
using System.Net.Http.Headers;

namespace MiniDebugger
{
    class Program
    {
        static NamedPipeServerStream server = new NamedPipeServerStream("Antivirus_Dbg");




        static Task Main(string[] args)
        {
            Console.Write("Нажмите Enter что бы выбрать модуль для загрузки....");
            Console.ReadLine();

            string ModulePath = String.Empty;

            {
                byte number = 0;
                string[] modulePaths = Directory.GetFiles("..\\Modules\\", "*.dll"); 
                foreach (string module in modulePaths)
                {
                    Console.WriteLine($"[{number++}]->" + module);
                }

                while (true)
                {
                    number = byte.Parse(Console.ReadLine());
                    if (number < 0 || number >= modulePaths.Length)
                        Console.WriteLine("Введите корректный номер");
                    else
                        break;
                }

                ModulePath = modulePaths[number];
            }



            /**/
            string name = ModulePath.Substring(ModulePath.LastIndexOf('\\') + 1);

            Console.Clear();
            Console.WriteLine("Загрузка модуля ->" + name);
            Console.WriteLine(ModulePath);

            Assembly moduleAssembly = Assembly.LoadFrom(ModulePath);
            {
                //Проверка существования инициализатора
                bool found = false;
                foreach (Type type in moduleAssembly.GetTypes())
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
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Класс инициализатора не найден");

                    Console.ReadKey();
                    return null;
                }
            }

            Type Initializator = moduleAssembly.GetType(name.Substring(0, name.Length - 3) + "Initializator");
            MethodInfo EntryPoint = Initializator.GetMethod("EntryPoint");
            if(EntryPoint == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Вход в модуль невозможен(Проблемы с точкой входа)");
            }

            /* ============================================================= */
            /* ============================================================= */
            /* ============================================================= */



            new Thread(pipeReceiver).Start();
            Thread.Sleep(500);

            EntryPoint.Invoke(null, new object[] { });
            FuncAfterEntryPoint();

            return Task.Delay(-1);
        }



        static void pipeReceiver()
        {
            Console.WriteLine("[DbgPipe] Ожидание подключения отлаживаемых модулей");
            server.WaitForConnection();
            Console.WriteLine("[DbgPipe] Подключён модуль");

            StreamReader DbgReader = new StreamReader(server, Encoding.Unicode);


            while (true)
            {
                string message = DbgReader.ReadLine();

                switch (message[0])
                {
                    case '0':
                        {
                            //info
                            Console.ForegroundColor = ConsoleColor.Green;
                            break;
                        }

                    case '1':
                        {
                            //warn
                            Console.ForegroundColor = ConsoleColor.Blue;
                            break;
                        }

                    case '2':
                        {
                            //error
                            Console.ForegroundColor = ConsoleColor.Red;
                            break;
                        }

                    default:
                        {
                            Console.ForegroundColor = ConsoleColor.White;
                            Console.WriteLine(message);
                            continue;
                        }
                }

                Console.WriteLine(message.Substring(1));
            }
        }

        public static void FuncAfterEntryPoint()
        {
            NamedPipeServerStream server = new NamedPipeServerStream("FileNamePipe");
            server.WaitForConnection();

            StreamReader reader = new StreamReader(server, Encoding.Unicode);

            while (true)
            {
                string msg = reader.ReadLine();
                Console.WriteLine("[FuncAfterEntryPoint] " + msg);
            }
        }
    }
}
