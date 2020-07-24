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
using System.Net.NetworkInformation;

namespace MiniDebugger
{
    class Program
    {
        static NamedPipeServerStream server;
        static List<int> IDs = new List<int>();


        static Task Main(string[] args)
        {
            System.Console.CancelKeyPress += OnClose;

            /*операнд 0 - r(receive) или s(sender) или c(command), мод работы программы*/
            if (args.Length > 0)
            {
                if (args[0] == "r")
                {
                    new Task(() => PipeReader(args[1])).Start();
                }
                else if (args[0] == "s")
                {
                    new Task(() => PipeWriter(args[1])).Start();
                }else if(args[0] == "c")
                {
                    new Task(() => CommandLine()).Start();
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

            /*Запуск "скриптов" отладки*/
            Debug_PartitionMon(EntryPoint);
            
            return Task.Delay(-1);
        }


        static void OnClose(object sender, ConsoleCancelEventArgs e)
        {
            foreach (int id in IDs) Process.GetProcessById(id).Kill();
        }

        /// <summary>
        /// Функция для приема и вывода информации, принимаемой по трубе
        /// </summary>
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


        ///<summary>
        /// Командная строка отладчика
        /// </summary>
        public static void CommandLine()
        {
            Console.WriteLine("Debugger command line");
            List<NamedPipeClientStream> PipeConnections = new List<NamedPipeClientStream>();

            while (true)
            {
                /* create <название именованной трубы, по которой так же будет производится прием>*/
                /* send <что отправить>        после нажатия Enter появляется список выбора, на какую трубу отправить*/
                /* conn <Название трубы>*/
                Console.Write("cmd -> ");
                string command = Console.ReadLine();

                switch (command.Substring(0, command.IndexOf(' ')))
                {
                    case "create":
                        {

                            break;
                        }

                    case "send":
                        {
                            Console.Write("Введите сообщение: ");
                            string message = Console.ReadLine();

                            if(PipeConnections.Count > 1)
                                foreach (NamedPipeClientStream client in PipeConnections) Console.WriteLine(client);
                            else
                            {
                                PipeConnections[0].Write(Encoding.Unicode.GetBytes(message), 0, message.Length * 2);
                            }

                            break;
                        }

                    case "conn":
                        {
                            PipeConnections.Append(new NamedPipeClientStream(command.Substring(command.IndexOf(' ')+1)));
                            Console.Write("Проба подключения к " + command.Substring(command.IndexOf(' ') + 1) + "...");

                            try
                            {
                                PipeConnections[PipeConnections.Count - 1].Connect(500);
                                Console.WriteLine("успешно");
                            }
                            catch
                            {
                                Console.WriteLine("не успешно");
                                PipeConnections.RemoveAt(PipeConnections.Count - 1);
                            }
                            break;
                        }
                }
            }
        }


        /// <summary>
        /// Мини "скрипт" для отладки модуля монитора разделов
        /// </summary>
        /// <param name="EntryPoint">Ссылка на точку входа</param>
        static void Debug_PartitionMon(MethodInfo EntryPoint)
        {
            //Создание процесса(отдельного окна) на чтение трубы FileNamePipe
            IDs.Add(Process.Start("MiniDebugger.exe", "r FileNamePipe").Id);

            Thread.Sleep(2000);
            EntryPoint.Invoke(null, new object[] { });

            //Конец скрипта, Создаем командную строку отладчика в новом окне
            IDs.Add(Process.Start("MiniDebugger.exe", "c").Id);            
        }
    }
}
