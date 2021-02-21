using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;

using System.Diagnostics;

namespace API_Client_Library
{
    public class ScannedFileInfo
    {
        public readonly string file;

        public ScannedFileInfo(string file)
        {
            this.file = file;
        }
    }

    public enum ActionType
    {
        Delete,
        ToQuarantine,
        Nothing
    }



    /// <summary>
    /// API ядра антивируса
    /// </summary>
    public static class API
    {
        /*=== events ===*/
        public delegate void scanCompetedEvent(string File);
        public delegate void scanFoundVirusEvent(VirusInfo File);
        public delegate void virusInfo(VirusInfo info);

        public static event scanCompetedEvent onScanCompleted;
        public static event scanFoundVirusEvent onScanFound;
        public static event virusInfo onVirusInfo;

        /*=== Connectors ===*/
        private static readonly NamedPipeServerStream InputConnector = new NamedPipeServerStream("API.User");
        private static readonly NamedPipeClientStream OutputConnector = new NamedPipeClientStream("API.Core");

        /// <summary>
        /// Поток обработки событий
        /// </summary>
        private static readonly Thread InputHandler = new Thread(Handler) { Name = "ApiHandler" };

        private static readonly BinaryWriter OutputWriter = new BinaryWriter(OutputConnector);
        public static Mutex Writer_sync = new Mutex();


        /// <summary>
        /// Код потока обработчика событий
        /// </summary>
        private static void Handler()
        {
            var reader = new BinaryReader(InputConnector);

            var code = 100;

            while (true)
            {
                try
                {
                    code = reader.ReadByte();
                }
                catch(EndOfStreamException)
                {
                    //Если ядро отключилось
                    break;
                }

                switch (code)
                {
                    case 0:
                        {
                            var file = reader.ReadString();
                            onScanCompleted.Invoke(file);
                            break;
                        }

                    case 1:
                        {
                            var SystemId = reader.ReadInt32();
                            var pathToFile = reader.ReadString();
                            var virusId = reader.ReadInt32();

                            onScanFound.Invoke(new VirusInfo(
                                pathToFile,
                                SystemId,
                                virusId,
                                false,
                                ""
                            ));

                            break;
                        }

                    case 2:
                        {
                            var SystemId = reader.ReadInt32();
                            var pathToFile = reader.ReadString();
                            var virusId = reader.ReadInt32();
                            var quarantine = reader.ReadBoolean();
                            var pathToFileInQuarantine = reader.ReadString();

                            onVirusInfo.Invoke(new VirusInfo(
                                pathToFile,
                                SystemId,
                                virusId,
                                quarantine,
                                pathToFileInQuarantine
                            ));

                            break;
                        }

                    case 3:
                        {
                            var SystemId = reader.ReadInt32();
                            var pathToFile = reader.ReadString();
                            var virusId = reader.ReadInt32();
                            var quarantine = reader.ReadBoolean();
                            var pathToFileInQuarantine = reader.ReadString();

                            onVirusInfo.Invoke(new VirusInfo(
                                pathToFile,
                                SystemId,
                                virusId,
                                quarantine,
                                pathToFileInQuarantine
                            ));

                            break;
                        }


                    default:
                        {
                            break;
                        }
                }
            }
        }

        /*=== Функционал ===*/

        /// <summary>
        /// Поместить вирус в карантин
        /// </summary>
        public static void ToQuarantine(int id)
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Перемещение в карантин {id}");
#endif
                OutputWriter.Write((byte)1);
                OutputWriter.Write(id);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        /// <summary>
        /// Восстановить файл из карантина
        /// </summary>
        public static void RestoreFile(int id)
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Восстановление из карантина {id}");
#endif
                OutputWriter.Write((byte)2);
                OutputWriter.Write(id);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        /// <summary>
        /// Получить информацию о вирусе
        /// </summary>
        public static void GetVirusInfo(int virusId)
        {

        }

        public static void SetDefenderState(bool state)
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Установить состояние защиты {state}");
#endif
                OutputWriter.Write((byte)14);
                OutputWriter.Write(state);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        public static void StopKernel()
        {
            Writer_sync.WaitOne();
            {

#if DEBUG
                Debug.WriteLine($"[api] Остановка ядра");
#endif
                OutputWriter.Write((byte)13);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        /// <summary>
        /// Применить действия для обнаруженных вирусов
        /// </summary>
        /// <param name="Info"></param>
        public static void ApplyingActions(VirusAction[] Info)
        {
            Writer_sync.WaitOne();

#if DEBUG
            Debug.WriteLine($"[api] Применение действий к вирусам");
#endif

            foreach (VirusAction info in Info)
            {
                switch (info.Action)
                {
                    case ActionType.Delete:
                        {
                            OutputWriter.Write((byte)3);
                            OutputWriter.Write(info.Info.id);
                            OutputWriter.Flush();

                            break;
                        }

                    case ActionType.ToQuarantine:
                        {
                            OutputWriter.Write((byte)1);
                            OutputWriter.Write(info.Info.id);
                            OutputWriter.Flush();

                            break;
                        }
                }
            }

            Writer_sync.ReleaseMutex();
        }

        /// <summary>
        /// Очистить очередь сканирования файлов
        /// </summary>
        public static void ClearScanQueue()
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Очистка очереди сканирования файлов");
#endif
                OutputWriter.Write((byte)7);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        /// <summary>
        /// Добавить в очередь сканирования
        /// </summary>
        public static void AddToScan(string file)
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Добавление в очередь сканирования {file}");
#endif
                OutputWriter.Write((byte)6);
                OutputWriter.Write(file);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        /// <summary>
        /// Автосканирование съемных носителей
        /// </summary>
        public static void SetAutoScanRemovableDevices(bool flag)
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Установка состояния автопроверки съемных носителей {flag}");
#endif
                OutputWriter.Write((byte)8);
                OutputWriter.Write(flag);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        public static void getAllViruses()
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Получить информацию о всех вирусах");
#endif
                OutputWriter.Write((byte)5);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        public static void DeleteFile(int id)
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Удалить файл {id}");
#endif
                OutputWriter.Write((byte)3);
                OutputWriter.Write(id);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        public static void ClearConnectedDevices()
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Очистить таблицу подключенных устройств");
#endif
                OutputWriter.Write((byte)9);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        public static void AddSimpleRule(string rule)
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Добавить простое правило {rule}");
#endif
                OutputWriter.Write((byte)10);
                OutputWriter.Write(rule);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        public static void RemoveSimpleRule(string rule)
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Удалить простое правило {rule}");
#endif
                OutputWriter.Write((byte)11);
                OutputWriter.Write(rule);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        public static void ClearSimpleRules()
        {
            Writer_sync.WaitOne();
            {
#if DEBUG
                Debug.WriteLine($"[api] Очистить простые правила");
#endif
                OutputWriter.Write((byte)12);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }
        /*=== Остальное ===*/

        public static void Init()
        {
#if DEBUG
            Debug.WriteLine("[api] подключение...");
#endif

            OutputConnector.Connect();

#if DEBUG
            Debug.WriteLine("[api] ожидание подключения ядра");
#endif

            InputConnector.WaitForConnection();

#if DEBUG
            Debug.WriteLine("[api] Запуск входящего обработчика");
#endif

            InputHandler.Start();
        }

        public static void ApiStop()
        {
#if DEBUG
            Debug.WriteLine("[api] Стоп, закрытие соединений");
#endif

            InputHandler.Abort();
            InputConnector.Close();
            OutputConnector.Close();
        }
    }

    public class VirusInfo
    {
        public string path;
        public int id;
        public int VirusId;

        public bool inQuarantine;
        public string pathInQuarantine;

        public VirusInfo(
            string path,
            int id,
            int VirusId,
            bool quarantine,
            string inQuarantine
            )
        {
            this.path = path;
            this.id = id;
            this.VirusId = VirusId;
            this.inQuarantine = quarantine;
            this.pathInQuarantine = inQuarantine;
        }
    }

    public class VirusAction
    {
        public readonly VirusInfo Info;
        public ActionType Action;

        public VirusAction(VirusInfo Info)
        {
            this.Info = Info;
        }
    }
}
