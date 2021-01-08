/*
    Наименование модуля: Filter(Фильтр)
    Описание модуля
        Служит для фильтрации проверяемых файлов
 */

using System;
using System.Xml;
using System.Collections.Generic;

namespace MODULE_FILTER
{
    public static class Filter
    {
        const string API_MON_PIPE = "API_MON_FILTER";
        const string DRIVER_MON_PIPE = "DRIVER_MON_FILTER";
        const string OUTPUT_PIPE_NAME = "FILE_QUEUE";




        private static List<string> UncheckedExtentions = new List<string>();
        private static List<string> UncheckedPatches    = new List<string>();

        public static bool CheckByFilename()
        {
            throw new NotImplementedException();
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
