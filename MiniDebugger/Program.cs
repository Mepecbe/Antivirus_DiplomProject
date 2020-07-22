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
using System.Diagnostics;

namespace MiniDebugger
{
    class Program
    {
        static NamedPipeServerStream server;


        static Task Main(string[] args)
        {
            /*операнд 0 - r(receive) или s(sender), мод работы программы*/
            if (args.Length == 2)
            {
                if (args[0] == "r")
                {
                    new Task(() => PipeReader(args[1])).Start();
                }
                else if (args[0] == "s")
                {
                    new Task(() => PipeWriter(args[1])).Start();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Неправильный операнд 0, должно быть r или s");
                    Console.ReadKey();
                    return null;
                }

                return Task.Delay(-1);
            }
            /*========*/

            server = new NamedPipeServerStream("Antivirus_Dbg");

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


            Console.Clear();
            new Thread(pipeReceiver).Start();


            DebugDetector(EntryPoint);
            
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

        /*====*/
        public static void PipeReader(string PipeName)
        {
            Console.WriteLine("PipeReader for \"{0}\"\nWait connection", PipeName);
            NamedPipeServerStream server = new NamedPipeServerStream(PipeName);
            server.WaitForConnection();
            Console.WriteLine("Connected!");

            StreamReader reader = new StreamReader(server, Encoding.Unicode);

            while (true)
            {
                string msg = reader.ReadLine();
                Console.WriteLine($"[{PipeName}] " + msg);
            }
        }

        public static void PipeWriter(string PipeName)
        {
            Console.WriteLine("PipeWriter for \"{0}\"", PipeName);
            NamedPipeClientStream server = new NamedPipeClientStream(PipeName);
            server.Connect();

            StreamWriter writer = new StreamWriter(server, Encoding.Unicode);

            while (true)
            {
                Console.Write("cmd -> ");
                writer.WriteLine(Console.ReadLine());
            }
        }
        /*====*/




        static void DebugDetector(MethodInfo EntryPoint)
        {
            //Создание процесса на чтение трубы FileNamePipe
            Process Reader = Process.Start("MiniDebugger.exe", "r FileNamePipe");
            
            Thread.Sleep(2000);
            EntryPoint.Invoke(null, new object[] { });
            




            while (true)
            {
                //Для команд
                /* create <название именованной трубы, по которой так же будет производится прием>*/
                /* send <название именованной трубы, в которую отправить> <что отправить>*/
                string command = Console.ReadLine();

                switch (command.Substring(0, command.IndexOf(' ')))
                {
                    case "create": { break; }
                    case "send": { break; }
                }
            }
        }
    }
}
