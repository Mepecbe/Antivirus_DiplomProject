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

        /// <summary> Точка инициализации модуля </summary>
        /// <param name="fileName">Имя файла, с информацией о не проверяемых путях и файлах</param>
        /// <returns>Статус</returns>
        public static byte EntryPoint(string fileName)
        {
            throw new NotImplementedException();
        }

        public static bool CheckByFilename()
        {
            throw new NotImplementedException();
        }
    }
}
