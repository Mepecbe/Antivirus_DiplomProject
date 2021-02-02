using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Core.Kernel.VirusesManager
{
    /// <summary>
    /// Класс отвечающий за найденные вирусы
    /// </summary>
    public static class FoundVirusesManager
    {
        private static List<VirusInfo> VirusesTable = new List<VirusInfo>();
        public static Mutex VirusesTable_sync = new Mutex();

        /// <summary>
        /// Добавить новый вирус в таблицу
        /// </summary>
        /// <param name="info"></param>
        public static void AddNewVirus(VirusInfo info)
        {
            VirusesTable_sync.WaitOne();
            {
                VirusesTable.Add(info);
            }
            VirusesTable_sync.ReleaseMutex();
        }

        public static VirusInfo getInfo(int id)
        {
            VirusInfo result = null;

            VirusesTable_sync.WaitOne();
            {
                for (int index = 0; index < VirusesTable.Count; index++)
                {
                    if (VirusesTable[index].id == id)
                    {
                        result = VirusesTable[index];
                        break;
                    }
                }
            }
            VirusesTable_sync.ReleaseMutex();

            return result;
        }

        /// <summary>
        /// Проверка существования такого файла в таблице обнаруженных вирусов
        /// </summary>
        public static bool Exists(string file)
        {
            bool result = false;
            VirusesTable_sync.WaitOne();
            {
                for (int index = 0; index < VirusesTable.Count; index++)
                {
                    if (VirusesTable[index].file == file)
                    {
                        result = true;
                        break;
                    }
                }
            }
            VirusesTable_sync.ReleaseMutex();

            return result;
        }

        public static VirusInfo[] getAllViruses()
        {
            return VirusesTable.ToArray();
        }

        /// <summary>
        /// Инициализация компонента
        /// </summary>
        public static void Init()
        {

        }
    }




    public class VirusInfo
    {
        public int id;
        public bool inQuarantine;       // Находится ли файл в карантине
        public string fileInQuarantine; // Путь к файлу в карантине
        public string file;             // Путь к файлу
        public int VirusId;

        public VirusInfo(int id, string file, int VirusId)
        {
            this.id = id;
            this.file = file;
            this.VirusId = VirusId;
            this.inQuarantine = false;
        }
    }
}
