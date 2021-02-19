/*
    Наименование модуля: Filter(Фильтр)
    Описание модуля
        Служит для фильтрации проверяемых файлов
 */

using System;
using System.Xml;
using System.Collections.Generic;

using System.Text;
using System.Text.RegularExpressions;

using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

using LoggerLib;

namespace MODULE__FILTER
{
    public static class Configuration
    {
        public static Encoding NamedPipeEncoding = Encoding.Unicode;
    }

    public static class Filter
    {
        public static class Connector
        {
            public static NamedPipeServerStream CommandPipe   = new NamedPipeServerStream("Filter.CommandPipe");
            public static BinaryReader CommandPipeReader = new BinaryReader(CommandPipe, Configuration.NamedPipeEncoding);

            /// <summary>
            /// Труба для приёма данных от драйвер коннектора
            /// </summary>
            public static NamedPipeServerStream DriverMonitor = new NamedPipeServerStream("DRIVER_MON_FILTER");
            public static BinaryReader DriverMonitorReader = new BinaryReader(DriverMonitor, Configuration.NamedPipeEncoding);

            /// <summary>
            /// Труба для приёма даных от API монитора
            /// </summary>
            public static NamedPipeServerStream ApiMonitor    = new NamedPipeServerStream("API_MON_FILTER");
            public static BinaryReader ApiMonitorReader = new BinaryReader(ApiMonitor, Configuration.NamedPipeEncoding);

            /// <summary>
            /// Выходная труба (к ядру)
            /// </summary>
            public static NamedPipeClientStream Kernel        = new NamedPipeClientStream("Filter.Output");
            public static BinaryWriter KernelPipeWriter = new BinaryWriter(Kernel, Configuration.NamedPipeEncoding);

            public static LoggerClient Logger = new LoggerClient("Logger.Filter", "Filter logger");

            public static void Init()
            {
#if DEBUG
                Logger.Init();
#endif
                Kernel.Connect();
            }
        }

        public static class ProcessingFlows
        {
            /// <summary>
            /// Обработчик сообщений от драйвера
            /// </summary>
            public static Thread Handler1 = new Thread(() =>
            {
                Connector.Logger.WriteLine("[Filter.DriverHandler] Ожидаю подключения драйвер коннектора");
                Connector.DriverMonitor.WaitForConnection();
                Connector.Logger.WriteLine("[Filter.DriverHandler] Драйвер коннектор подключен", LogLevel.OK);
            })
            { Name = "DriverHandler" };

            /// <summary>
            /// Обработчик сообщений от API монитора
            /// </summary>
            public static Thread Handler2 = new Thread(() =>
            {
                Connector.Logger.WriteLine("[Filter.ApiMonHandler] Ожидаю подключения API монитора");

                Connector.ApiMonitor.WaitForConnection();

                Connector.Logger.WriteLine("[Filter.ApiMonHandler] API монитор подключен", LogLevel.OK);


                while (true)
                {
                    string buffer = Connector.ApiMonitorReader.ReadString();

                    Connector.Logger.WriteLine($"[Filter.ApiMonHandler] ПРОЧИТАНО {buffer}");

                    if (!FiltrationRules.ApplyFilter(buffer))
                    {
                        Connector.KernelPipeWriter.Write(buffer);
                        Connector.KernelPipeWriter.Flush();
                    }
                    else
                    {
                        Connector.Logger.WriteLine("[Filter.ApiMonHandler] ПУТЬ ОТФИЛЬТРОВАН ->" + buffer, LogLevel.WARN);
                    }
                }
            })
            { Name = "ApiMonHandler" };

            /// <summary>
            /// Обработчик команд
            /// </summary>
            public static Thread CommandHandler = new Thread(() =>
            {
                Connector.Logger.WriteLine("[Filter.CommandHandler] Активен! Ожидание подключения", LogLevel.WARN);

                Connector.CommandPipe.WaitForConnection();
                var Reader = new BinaryReader(Connector.CommandPipe, Encoding.Unicode);

                Connector.Logger.WriteLine("[Filter.CommandHandler] Подключен", LogLevel.OK);

                while (true)
                {
                    Connector.Logger.WriteLine("[Filter.CommandHandler] Ожидаю команду");
                    var code = Reader.ReadByte();

                    switch (code)
                    {
                        //Добавить правило фильтрации(расширение)
                        case 0:
                            {
                                var rule = Reader.ReadString();
                                FiltrationRules.Extentions.Add(new Regex(rule)); 
                                
                                Connector.Logger.WriteLine("[Filter.CommandHandler] Добавлено правило фильтрации расширения ->" + rule, LogLevel.OK);
                                break;
                            }

                        //Добавить правило фильтрации(путь)
                        case 1:
                            {
                                var rule = Reader.ReadString();
                                FiltrationRules.Paths.Add(new Regex(rule));

                                Connector.Logger.WriteLine("[Filter.CommandHandler] Добавлено правило фильтрации путя ->" + rule, LogLevel.OK);
                                break;
                            }

                        //Добавить правило фильтрации(другое)
                        case 2:
                            {
                                var rule = Reader.ReadString();
                                FiltrationRules.OtherRules.Add(new Regex(rule));

                                Connector.Logger.WriteLine("[Filter.CommandHandler] Добавлено правило фильтрации ->" + rule, LogLevel.OK);
                                break;
                            }

                        //Добавить простое правило
                        case 3:
                            {
                                var rule = Reader.ReadString();
                                FiltrationRules.SimpleRules.Add(rule);

                                Connector.Logger.WriteLine("[Filter.CommandHandler] Добавлено простое правило фильтрации ->" + rule, LogLevel.OK);
                                break;
                            }

                        //Удалить простое правило
                        case 4:
                            {
                                var rule = Reader.ReadString();
                                if (FiltrationRules.SimpleRules.Remove(rule))
                                {
                                    Connector.Logger.WriteLine("[Filter.CommandHandler] Удалено простое правило фильтрации ->" + rule, LogLevel.OK);
                                } 
                                else
                                {
                                    Connector.Logger.WriteLine("[Filter.CommandHandler] Простое правило для удаления не найдено");
                                }

                                break;
                            }

                        //Удалить все простые правила
                        case 5:
                            {
                                FiltrationRules.SimpleRules.Clear();
                                Connector.Logger.WriteLine("[Filter.CommandHandler] Удалены все простые правила", LogLevel.OK);
                                
                                break;
                            }

                        //Выключение
                        case 6:
                            {
                                Connector.Logger.WriteLine("[Filter.CommandHandler] Выключение", LogLevel.OK);

                                Handler1.Abort();
                                Handler2.Abort();


                                CommandHandler.Abort();

                                break;
                            }

                        //Удалить все правила (регулярные выражения)
                        case 7:
                            {
                                FiltrationRules.Extentions.Clear();
                                FiltrationRules.OtherRules.Clear();
                                FiltrationRules.Paths.Clear();

                                break;
                            }
                    }
                }
            })
            { Name = "CommandHandler" };


            public static void Init()
            {
                //Handler1.Start();
                Handler2.Start();
                CommandHandler.Start();
            }
        }

        /// <summary>
        /// Правила фильтрации, если входная строка(а это путь к файлу) попадает под хотя бы одно правило, файл не отправляется на проверку
        /// </summary>
        public static class FiltrationRules
        {
            public delegate bool handler(string input);


            /// <summary>
            /// Остальные правила
            /// </summary>
            public static List<Regex> OtherRules = new List<Regex>();

            /// <summary>
            /// Простые правила
            /// Если строка существует в подстроке - фильтр сработал
            /// </summary>
            public static List<string> SimpleRules = new List<string>();

            /// <summary>
            /// Фильтруемые расширения
            /// ([^\s]+(?=\.(jpg|gif|png))\.\w)
            /// </summary>
            public static List<Regex> Extentions = new List<Regex>();

            /// <summary>
            /// Фильтруемые пути к файлам
            /// </summary>
            public static List<Regex> Paths = new List<Regex>();

            /// <summary>
            /// Прочие обработчики 
            /// </summary>
            public static List<handler> OtherHandlers = new List<handler>();


            public static bool ApplyFilter(string input)
            {
                if (Step1(input) || Step2(input) || Step3(input) || CheckSimpleRules(input))
                {
                    return true;
                }
                else
                {
                    for(byte index = 0; index < OtherHandlers.Count; index++)
                    {
                        if (OtherHandlers[index].Invoke(input))
                        {
                            return true;
                        }
                    }
                }

                return false;
            }

            /// <summary>
            /// Шаг 1 - фильтрация расширений
            /// </summary>
            /// <param name="input"></param>
            /// <returns></returns>
            public static bool Step1(string input)
            {
                foreach (Regex rg in Extentions)
                {
                    if (rg.IsMatch(input))
                    {
                        return true;
                    }
                }

                return false;
            }

            /// <summary>
            /// Шаг 2 - фильтрация путей
            /// </summary>
            /// <param name="input"></param>
            /// <returns></returns>
            public static bool Step2(string input)
            {
                foreach (Regex rg in Paths)
                {
                    if (rg.IsMatch(input))
                    {
                        return true;
                    }
                }

                return false;
            }

            /// <summary>
            /// Шаг 3 - прочие правила фильтрации
            /// </summary>
            /// <param name="input"></param>
            /// <returns></returns>
            public static bool Step3(string input)
            {
                foreach (Regex rg in OtherRules)
                {
                    if (rg.IsMatch(input))
                    {
                        return true;
                    }
                }

                return false;
            }

            public static bool CheckSimpleRules(string input)
            {
                foreach(string rule in SimpleRules)
                {
                    if (input.Contains(rule))
                    {
                        return true;
                    }
                }

                return false;
            }

            /// <summary>
            /// Инициализация стандартных правил
            /// </summary>
            public static void InitDefaultRules()
            {
                {
                    //Фильтрация путей к папке
                    OtherHandlers.Add((string path) =>
                    {
                        if (path.LastIndexOf('.') < path.LastIndexOf('\\'))
                            return true;

                        return false;
                    });
                }
            }

            public static void AddOtherRule(Regex rule)
            {
                OtherRules.Add(rule);
            }
        }
    }



    public static class Initializator
    {
        public static byte EntryPoint()
        {
            Filter.Connector.Init();
            Filter.FiltrationRules.InitDefaultRules();
            Filter.ProcessingFlows.Init();

            return 0;
        }
    }
}
