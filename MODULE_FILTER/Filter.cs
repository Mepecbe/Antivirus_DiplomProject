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
