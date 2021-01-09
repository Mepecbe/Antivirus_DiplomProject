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

namespace MODULE_FILTER
{
    public static class Filter
    {
        public static class Connector
        {
            const string API_MON_PIPE = "API_MON_FILTER";        /* Труба для приёма данных от монитора разделов по API */
            const string DRIVER_MON_PIPE = "DRIVER_MON_FILTER";  /* Труба для приёма данных от монитора разделов использующего драйвер*/
            const string OUTPUT_PIPE_NAME = "FILE_QUEUE";        /* Выходная труба (соединяющая с ядром)*/

            public static NamedPipeServerStream DriverMonitor = new NamedPipeServerStream(DRIVER_MON_PIPE);
            public static NamedPipeServerStream ApiMonitor    = new NamedPipeServerStream(DRIVER_MON_PIPE);
            public static NamedPipeClientStream Kernel        = new NamedPipeClientStream(OUTPUT_PIPE_NAME);
        }

        public static class ProcessingFlows
        {
            /// <summary>
            /// Обработчик сообщений от драйвера
            /// </summary>
            public static Thread Handler1 = new Thread(() =>
            {

            });

            /// <summary>
            /// Обработчик сообщений от API монитора
            /// </summary>
            public static Thread Handler2 = new Thread(() =>
            {

            });
        }

        /// <summary>
        /// Правила фильтрации, если входная строка(а это путь к файлу)
        /// </summary>
        public static class FiltrationRules
        {
            /// <summary>
            /// Остальные правила
            /// </summary>
            public static Regex[] OtherRules = new Regex[0];

            /// <summary>
            /// Фильтруемые расширения
            /// </summary>
            public static Regex[] Extentions = new Regex[0];

            /// <summary>
            /// Фильтруемые пути к файлам
            /// </summary>
            public static Regex[] Paths = new Regex[0];


        }
    }


    public static class Initializator
    {
        public static byte EntryPoint()
        {
            return 0;
        }
    }
}
