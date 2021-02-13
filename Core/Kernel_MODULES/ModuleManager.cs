using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

using Core.Kernel.Connectors;
using Core;

namespace Core.Kernel.ModuleLoader
{
    public static class ModuleManager
    {
        public static List<Module> Modules = new List<Module>();
        public static class Loader
        {           
            public static void LoadModule(string ModuleFileName)
            {
                Modules.Add(new Module(ModuleFileName));
            }
        }

        /// <summary>
        /// Представляет собой модуль, а так же загрузчик
        /// </summary>
        public class Module
        {
            public readonly string ModuleName;
            public readonly Assembly ModuleAssembly;
            public bool IsRunning { private set; get; }

            public Module(string ModuleFileName)
            {
                this.IsRunning = false;
                this.ModuleName = ModuleFileName;

                try
                {
                    this.ModuleAssembly = Assembly.LoadFrom("Modules\\" + ModuleFileName);
                }
                catch
                {
#warning Обработка ошибки сборки
                    return;
                }

                {
                    //Проверка существования класса инициализатора
                    bool found = false;
                    foreach (Type type in this.ModuleAssembly.GetTypes())
                    {
                        if (type.Name == "Initializator")
                        {
                            found = true;
                            break;
                        }
                    }

                    if (!found)
                    {
                        KernelConnectors.Logger.WriteLine($"[Kernel.ModuleLoader] {ModuleFileName} Инициализатор не найден", LoggerLib.LogLevel.ERROR);

                        //Не найден класс инициализатора
                        return;
                    }
                }

                //Вход в модуль
                {
                    Type InitializatorType = this.ModuleAssembly.GetType(ModuleFileName.Substring(0, ModuleFileName.Length - 3) + "Initializator", true, true);
                    MethodInfo EntryPoint = InitializatorType.GetMethod("EntryPoint");

                    if (EntryPoint == null)
                    {
                        KernelConnectors.Logger.WriteLine($"[Kernel.ModuleLoader] {ModuleFileName} точка входа в модуль не найдена", LoggerLib.LogLevel.ERROR);
                        return;
                    }
                    else
                    {
                        object result = EntryPoint.Invoke(null, new object[] { });

                        if ((byte)result == 0)
                        {
                            this.IsRunning = true;
                        }
                    }
                }
            }
        }
    }
}
