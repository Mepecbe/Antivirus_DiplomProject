using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

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

                this.ModuleAssembly = Assembly.LoadFrom("Modules\\" + ModuleFileName);

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
#if DEBUG
                        Console.WriteLine("Инициализатор библиотеки не найден");
#endif
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
