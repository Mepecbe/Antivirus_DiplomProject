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

namespace MODULE__FILTER
{
    public static class Filter
    {
        public static class Connector
        {
            public static NamedPipeServerStream DriverMonitor = new NamedPipeServerStream("DRIVER_MON_FILTER"); /* Труба для приёма данных от монитора разделов использующего драйвер*/
            public static NamedPipeServerStream ApiMonitor    = new NamedPipeServerStream("API_MON_FILTER");    /* Труба для приёма данных от монитора разделов по API */
            public static NamedPipeClientStream Kernel        = new NamedPipeClientStream("Filter.Output");        /* Выходная труба (соединяющая с коннектором ядра)*/
        }

        public static class ProcessingFlows
        {
            /// <summary>
            /// Обработчик сообщений от драйвера
            /// </summary>
            public static Thread Handler1 = new Thread(() =>
            {
#warning "Необходимо определять тип операции, создание или изменение"
#if DEBUG
                Console.WriteLine("[Filter.Thr.Handler1] Active! Wait connection");
#endif
                Connector.DriverMonitor.WaitForConnection();
#if DEBUG
                Console.WriteLine("[Filter.Thr.Handler1] Connected");
#endif


            });

            /// <summary>
            /// Обработчик сообщений от API монитора
            /// </summary>
            public static Thread Handler2 = new Thread(() =>
            {
#if DEBUG
                Console.WriteLine("[Filter.Thr.Handler2] Active! Wait connection");
#endif
                Connector.ApiMonitor.WaitForConnection();
                StreamReader Reader = new StreamReader(Connector.ApiMonitor, Encoding.Unicode);
                StreamWriter Writer = new StreamWriter(Connector.Kernel, Encoding.Unicode) { AutoFlush = true };
#if DEBUG
                Console.WriteLine("[Filter.Thr.Handler2] Connected");
#endif

                while (true)
                {
                    string buffer = Reader.ReadLine();

                    if (!FiltrationRules.ApplyFilter(buffer))
                    {
                        Writer.WriteLine(buffer);
                    }

                }
            });
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
            /// Фильтруемые расширения
            /// ([^\s]+(?=\.(jpg|gif|png))\.\w)
            /// </summary>
            public static List<Regex> Extentions = new List<Regex>();

            /// <summary>
            /// Фильтруемые пути к файлам
            /// </summary>
            public static List<Regex> Paths = new List<Regex>();

            public static List<handler> OtherHandlers = new List<handler>();


            public static bool ApplyFilter(string input)
            {
                if (Step1(input) || Step2(input) || Step3(input))
                {
                    return true;
                }
                else
                {
                    for(byte index = 0; index < OtherHandlers.Count; index++)
                    {
                        if (OtherHandlers[index].Invoke(input))
                        {
                            Console.WriteLine("OTHER HANDLER FILTERED ->" + input);
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

            /// <summary>
            /// Инициализация стандартных правил
            /// </summary>
            public static void InitDefaultRules()
            {
                {
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
            Filter.FiltrationRules.InitDefaultRules();

            // Необходимо сначала подключить модуль к ядру
            Filter.Connector.Kernel.Connect();

            Filter.ProcessingFlows.Handler1.Start();
            Filter.ProcessingFlows.Handler2.Start();

               

            return 0;
        }
    }
}
