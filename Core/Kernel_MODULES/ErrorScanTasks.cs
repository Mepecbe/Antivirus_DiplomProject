using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Core.Kernel.ScanModule;
using Core.Kernel.VirusesManager;

namespace Core.Kernel.ErrorTasks
{
    /// <summary>
    /// Менеджер задач сканирования завершенных с ошибкой
    /// </summary>
    public static class ErrorScanTasksManager
    {
        private static List<ErrorScanTask> ErrorScanTasks = new List<ErrorScanTask>();
        public static int Count { get { return ErrorScanTasks.Count; } }
        
        public static void Add(byte code, string message, ScanTask task)
        {
            ErrorScanTasks.Add(new ErrorScanTask(code, message, task));
        }

        /// <summary>
        /// Удалить все записи о задачах сканирования завершенных с ошибкой
        /// </summary>
        public static void Clear()
        {
            ErrorScanTasks.Clear();
        }

        public static void Init()
        {

        }
    }


    public class ErrorScanTask
    {
        public readonly string ErrorMessage;
        public readonly byte ErrorCode;
        public readonly ScanTask task;

        public ErrorScanTask(byte code, string message, ScanTask task)
        {
            this.ErrorCode = code;
            this.ErrorMessage = message;
            this.task = task;
        }
    }
}
