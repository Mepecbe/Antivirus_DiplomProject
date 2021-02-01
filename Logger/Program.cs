using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;

namespace Logger
{
    static class Conf
    {
        public const byte MAX_PIPES = 20;
        public static readonly Mutex GlobalSync = new Mutex();

        public const ConsoleColor WARN_COLOR = ConsoleColor.Yellow;
        public const ConsoleColor INFO_COLOR = ConsoleColor.White;
        public const ConsoleColor ERROR_COLOR = ConsoleColor.Red;
        public const ConsoleColor OK_COLOR = ConsoleColor.Green;
        public const ConsoleColor DEFAULT_COLOR = ConsoleColor.Black;

        public static Dictionary<string, string> Loggers = new Dictionary<string, string>() {
            { "Logger.Modules.Scanner", "Service Scanner logger" },
            { "Logger.Kernel", "Service Scanner logger" },
            { "Logger.Filter", "Service Filter logger" },
            { "Logger.ApiMonitor", "Service FileSysApiMon logger" }
        };
    }

    class Logger
    {
        public NamedPipeServerStream inputPipe;
        public string Name { get; private set; }
        public string PipeName { get; private set; }
        public Thread HandlerThread;

        private void Handler()
        {
            inputPipe.WaitForConnection();
            var reader = new BinaryReader(inputPipe);

            Console.WriteLine($"[*] Pipe {PipeName} connected");

            while (true)
            {
                var msg = reader.ReadString();

                byte logLevel = 0;

                try
                {
                    logLevel = byte.Parse(msg[0].ToString());
                }
                catch(Exception ex)
                {
                    Console.WriteLine($"[Logger] unknown error {ex.Message}");
                    continue;
                }

                Conf.GlobalSync.WaitOne();
                {
                    switch (logLevel)
                    {
                        //WARN
                        case 0:
                            {
                                Console.ForegroundColor = Conf.WARN_COLOR;
                                break;
                            }

                        //INFO
                        case 1:
                            {
                                Console.ForegroundColor = Conf.INFO_COLOR;
                                break;
                            }

                        //ERROR
                        case 2:
                            {
                                Console.ForegroundColor = Conf.ERROR_COLOR;
                                break;
                            }

                        //OK
                        case 3:
                            {
                                Console.ForegroundColor = Conf.OK_COLOR;
                                break;
                            }
                    }

                    Console.WriteLine($"[{PipeName}] {msg.Substring(2)}");

                    Console.ForegroundColor = Conf.DEFAULT_COLOR;
                }
                Conf.GlobalSync.ReleaseMutex();
            }
        }
        
        public Logger(string pipeName, string loggerName)
        {
            this.Name = loggerName;
            this.PipeName = pipeName;

            inputPipe = new NamedPipeServerStream(pipeName);
            HandlerThread = new Thread(Handler);
            HandlerThread.Start();
        }
    }

    class Program
    {
        static List<Logger> Loggers = new List<Logger>();

        static async Task Main(string[] args)
        {
            var keys = Conf.Loggers.Keys;

            foreach (var key in keys)
            {
                Console.WriteLine($"Create {key} => ${Conf.Loggers[key]}");
                Loggers.Add(new Logger(key, Conf.Loggers[key]));
            }

            await Task.Delay(-1);
        }
    }
}
