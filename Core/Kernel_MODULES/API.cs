using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

using Core.Kernel.Connectors;
using Core.Kernel.ScanModule;
using Core.Kernel.Quarantine;
using Core.Kernel.VirusesManager;
using Core.Kernel.ErrorTasks;

using Core.Kernel.ModuleLoader;
using System.Diagnostics;

namespace Core.Kernel.API
{
    static class API
    {
        private static Thread RequestHandler = new Thread(Handler);

        private static NamedPipeClientStream UserOutputConnector;
        private static NamedPipeServerStream UserInputConnector;

        private static BinaryWriter Out_writer;


        private static void Handler()
        {
            var binaryReader = new BinaryReader(UserInputConnector);
            Out_writer = new BinaryWriter(UserOutputConnector);

#if DEBUG
            Console.WriteLine("[API] Init success");
#endif
            byte code = 255;

            while (true)
            {
                KernelConnectors.Api_In_Sync.WaitOne();

                {
                    try
                    {
                        code = binaryReader.ReadByte();
                    }
                    catch
                    {
#if DEBUG
                        Console.WriteLine("[API] Чтение завершилось ошибкой");
#endif
                        if (!UserInputConnector.IsConnected)
                        {
#if DEBUG
                            Console.WriteLine("[API] Ожидание переподключения пользователя");
#endif
                            UserInputConnector.WaitForConnection();

                            if (!UserOutputConnector.IsConnected)
                            {
#if DEBUG
                                Console.WriteLine("[API] Переподключение к пользователю");
#endif
                                UserOutputConnector.Connect();
                            }


                            KernelConnectors.Api_In_Sync.ReleaseMutex();
                            continue;
                        }
                    }

#if DEBUG
                    Console.WriteLine($"[API] Запрос, код {code}");
#endif

                    switch (code)
                    {
                        //Запрос на
                        case 0:
                            {

                                break;
                            }

                        //Запрос на перемещение файла в карантин
                        case 1:
                            {
                                var id = binaryReader.ReadInt32();
                                ToQuarantine(id);

                                break;
                            }

                        //Запрос на восстановление файла из карантина
                        case 2:
                            {
                                var id = binaryReader.ReadInt32();
                                Restore(id);

                                break;
                            }

                        //Запрос на удаление файла
                        case 3:
                            {
                                var id = binaryReader.ReadInt32();
                                Delete(id);

                                break;
                            }

                        //Запрос информации о вирусе
                        case 4:
                            {
                                var id = binaryReader.ReadInt32();
                                getVirusInfo(id);
                                break;
                            }

                        //Запрос информации о всех вирусах
                        case 5:
                            {
                                getAllVirusesInfo();
                                break;
                            }

                        //Просканировать файл
                        case 6:
                            {
                                string file = binaryReader.ReadString();

#if DEBUG
                                Console.WriteLine("[API] Добавление задачи " + file);
#endif

                                if (ScanTasks.Add(file) is null)
                                {
#if DEBUG
                                    Console.WriteLine("[API] Ошибка добавления задачи, проверка завершена");
#endif
                                    API_ScanCompleted(0, false, 0, file);
                                } 

                                break;
                            }

                        //Очистить очередь сканирования
                        case 7:
                            {
                                KernelConnectors.ScannerService_Command_Sync.WaitOne();
                                {
                                    ScanTasks.ClearQueue();
                                }
                                KernelConnectors.ScannerService_Command_Sync.ReleaseMutex();
                                break;
                            }

                        //Включение/выключение автоматической проверки съемных носителей
                        case 8:
                            {
                                var flag = binaryReader.ReadBoolean();

                                if (flag)
                                {
                                    KernelConnectors.PartitionMon_CommandWriter.Write("2*");
                                }
                                else
                                {
                                    KernelConnectors.PartitionMon_CommandWriter.Write("3*");
                                }

                                KernelConnectors.PartitionMon_CommandWriter.Flush();
                                break;
                            }

                        //Очистить информацию о подключенных устройствах
                        case 9:
                            {
                                KernelConnectors.PartitionMon_CommandWriter.Write("4*");
                                KernelConnectors.PartitionMon_CommandWriter.Flush();
                                break;
                            }

                        //Добавить простое правило фильтрации
                        case 10:
                            {
                                string rule = binaryReader.ReadString();
                                KernelConnectors.Filter_CommandWriter.Write((byte)3);
                                KernelConnectors.Filter_CommandWriter.Write(rule);

                                KernelConnectors.Filter_CommandWriter.Flush();
                                break;
                            }

                        //Удалить простое правило фильтрации
                        case 11:
                            {
                                string rule = binaryReader.ReadString();
                                KernelConnectors.Filter_CommandWriter.Write((byte)4);
                                KernelConnectors.Filter_CommandWriter.Write(rule);

                                KernelConnectors.Filter_CommandWriter.Flush();
                                break;
                            }

                        //Удалить все простые правила фильтрации
                        case 12:
                            {
                                KernelConnectors.Filter_CommandWriter.Write((byte)5);
                                KernelConnectors.Filter_CommandWriter.Flush();
                                break;
                            }

                        //Отключить всё
                        case 13:
                            {
#if DEBUG
                                Console.WriteLine("[API] Выключение ядра");
#endif

                                ScanTasks.Stop();

                                {
#if DEBUG
                                    Console.WriteLine("[API] Выключение фильтра ");
#endif
                                    KernelConnectors.Filter_CommandWriter.Write((byte)6);

#if DEBUG
                                    Console.WriteLine("[API] Выключение монитора разделов ");
#endif
                                    KernelConnectors.PartitionMon_CommandWriter.Write("7*");

#if DEBUG
                                    Console.WriteLine("[API] Выключение сканнера ");
#endif
                                    KernelConnectors.ScannerService_CommandWriter.Write((byte)1);

#if DEBUG
                                    Console.WriteLine("[API] Выключение вирусной БД");
#endif
                                    KernelConnectors.VirusesDb_CommandWriter.Write("/shutdown");
                                }

#if DEBUG
                                Console.WriteLine("[API] Закрытие подключений");
#endif
                                KernelConnectors.Stop();


                                Process.GetCurrentProcess().Kill();

#if DEBUG
                                Console.WriteLine("[API] Отключение обработчика API");
#endif
                                RequestHandler.Abort();

                                break;
                            }

                        case 14:
                            {
                                Defender(binaryReader.ReadBoolean());
                                break;
                            }

                        default:
                            {
#if DEBUG
                                Console.WriteLine("[API] Unknown request");
#endif
                                break;
                            }
                    }
                }

                KernelConnectors.Api_In_Sync.ReleaseMutex();
            }
        }

        private static void API_ScanCompleted(int id, bool found, int virusId, string file)
        {
            if (!UserOutputConnector.IsConnected)
            {
                return;
            }

            KernelConnectors.Api_Out_Sync.WaitOne();
            {
                if (found)
                {
                    //Идентификатор 
                    Out_writer.Write((byte)1);
                    Out_writer.Write(id);
                    Out_writer.Write(file);
                    Out_writer.Write(virusId);
                }
                else
                {
                    Out_writer.Write((byte)0);
                    Out_writer.Write(file);
                }

                Out_writer.Flush();
            }
            KernelConnectors.Api_Out_Sync.ReleaseMutex();
        }

        /// <summary>
        /// Переместить файл в карантин
        /// </summary>
        /// <param name="id"></param>
        private static void ToQuarantine(int id)
        {
            var virusInfo = FoundVirusesManager.getInfo(id);
            Quarantine.Quarantine.MoveVirusToQuarantine(id);
        }

        /// <summary>
        /// Восстановить файл
        /// </summary>
        /// <param name="id"></param>
        private static void Restore(int id)
        {
            var virusInfo = FoundVirusesManager.getInfo(id);
            ScanTasks.RestoredFile = virusInfo.file;


            KernelConnectors.Logger.WriteLine("[API.Restore] Восстановление файла " + virusInfo.file, LoggerLib.LogLevel.OK); 
            KernelConnectors.Logger.WriteLine("[API.Restore]   Удаление информации о вирусе из менеджера", LoggerLib.LogLevel.OK);
            FoundVirusesManager.Delete(id);

            KernelConnectors.Logger.WriteLine("[API.Restore]   Вызов восстановления файла у менеджера карантина", LoggerLib.LogLevel.OK);
            Quarantine.Quarantine.Restore(virusInfo.fileInQuarantine, virusInfo.file);
        }

        /// <summary>
        /// Удалить файл, где бы он не находился(в карантине/на диске)
        /// </summary>
        /// <param name="id"></param>
        private static void Delete(int id)
        {
            var virusInfo = FoundVirusesManager.getInfo(id);

            if (virusInfo.inQuarantine)
            {
                KernelConnectors.Logger.WriteLine($"[API] Удаление файла из карантина {virusInfo.fileInQuarantine}", LoggerLib.LogLevel.OK);
                Quarantine.Quarantine.DeleteFromStorage(id);
            }
            else
            {
                KernelConnectors.Logger.WriteLine($"[API] Удаление файла на жестком диске {virusInfo.file}", LoggerLib.LogLevel.OK);
                File.Delete(virusInfo.file);
            }

            KernelConnectors.Logger.WriteLine($"[API] Удаление из менеджера вирусов", LoggerLib.LogLevel.OK);

            FoundVirusesManager.Delete(id);
        }

        private static void getVirusInfo(int id)
        {
            var virusInfo = FoundVirusesManager.getInfo(id);

            if(virusInfo == null)
            {
                return;
            }

            KernelConnectors.Api_Out_Sync.WaitOne();
            {
                Out_writer.Write((byte)2);
                Out_writer.Write(virusInfo.id);
                Out_writer.Write(virusInfo.file);
                Out_writer.Write(virusInfo.VirusId);
                Out_writer.Write(virusInfo.inQuarantine);

                Out_writer.Write(virusInfo.fileInQuarantine is null ? " " : virusInfo.fileInQuarantine);
                Out_writer.Flush();
            }
            KernelConnectors.Api_Out_Sync.ReleaseMutex();
        }

        private static void getAllVirusesInfo()
        {
            KernelConnectors.Api_Out_Sync.WaitOne();
            {
                foreach(VirusInfo virusInfo in FoundVirusesManager.getAllViruses())
                {
                    Out_writer.Write((byte)2);
                    Out_writer.Write(virusInfo.id);
                    Out_writer.Write(virusInfo.file);
                    Out_writer.Write(virusInfo.VirusId);
                    Out_writer.Write(virusInfo.inQuarantine);

                    Out_writer.Write(virusInfo.fileInQuarantine is null ? " " : virusInfo.fileInQuarantine);

                    Out_writer.Flush();
                }
            }
            KernelConnectors.Api_Out_Sync.ReleaseMutex();
        }

        private static void Defender(bool flag)
        {
            KernelConnectors.PartitionMon_CommandPipe_Sync.WaitOne();
            if (flag)
            {
                KernelConnectors.PartitionMon_CommandWriter.Write("5*");
            }
            else
            {
                KernelConnectors.PartitionMon_CommandWriter.Write("6*");
            }
            KernelConnectors.PartitionMon_CommandPipe_Sync.ReleaseMutex();
        }


        public static void Init()
        {
            UserOutputConnector = KernelConnectors.Api_Out;
            UserInputConnector = KernelConnectors.Api_In;

            ScannerResponseHandler.onScanCompleted += API_ScanCompleted;

            RequestHandler.Start();
        }
    }
}
