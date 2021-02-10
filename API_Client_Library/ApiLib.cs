using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;

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

    public class VirusFileInfo
    {
        public readonly int kernelId;
        public readonly int virusId;
        public readonly string file;
        public ActionType Action;

        public VirusFileInfo(int id, int virusId, string file)
        {
            this.kernelId = id;
            this.virusId = virusId;
            this.file = file;
        }
    }


    /// <summary>
    /// API ядра антивируса
    /// </summary>
    public static class API
    {
        /*=== events ===*/
        public delegate void scanCompetedEvent(ScannedFileInfo File);
        public delegate void scanFoundVirusEvent(VirusFileInfo File);
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
                            ScanCompleted(reader);
                            break;
                        }

                    case 1:
                        {
                            var pathToFile = reader.ReadString();
                            var SystemId = reader.ReadInt32();
                            var virusId = reader.ReadInt32();
                            var inQuarantine = reader.ReadBoolean();
                            var pathInQuarantine = reader.ReadString();

                            onVirusInfo.Invoke(new VirusInfo(
                                pathToFile,
                                SystemId,
                                virusId,
                                inQuarantine,
                                pathInQuarantine
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

        public static int countt = 0;

        /*=== ОБРАБОТЧИКИ ===*/
        private static void ScanCompleted(BinaryReader dataReader)
        {
            var kernelId = dataReader.ReadInt32();
            var isVirus = dataReader.ReadBoolean();
            var virusId = dataReader.ReadInt32();
            var file = dataReader.ReadString();

            countt++;

            if (isVirus)
            {
                onScanFound.Invoke(new VirusFileInfo(kernelId, virusId, file));
            }
            else
            {
                onScanCompleted.Invoke(new ScannedFileInfo(file));
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

        /// <summary>
        /// Применить действия для обнаруженных вирусов
        /// </summary>
        /// <param name="Info"></param>
        public static void ApplyingActions(VirusFileInfo[] Info)
        {
            Writer_sync.WaitOne();

            foreach (VirusFileInfo info in Info)
            {
                switch (info.Action)
                {
                    case ActionType.Delete:
                        {
                            OutputWriter.Write((byte)3);
                            OutputWriter.Write(info.kernelId);
                            OutputWriter.Flush();

                            break;
                        }

                    case ActionType.ToQuarantine:
                        {
                            OutputWriter.Write((byte)1);
                            OutputWriter.Write(info.kernelId);
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
                OutputWriter.Write((byte)5);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        public static void DeleteFile(int id)
        {
            Writer_sync.WaitOne();
            {
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
                OutputWriter.Write((byte)9);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }

        public static void AddSimpleRule(string rule)
        {
            Writer_sync.WaitOne();
            {
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
                OutputWriter.Write((byte)12);
                OutputWriter.Flush();
            }
            Writer_sync.ReleaseMutex();
        }
        /*=== Остальное ===*/

        public static void Init()
        {
            Console.WriteLine("[api] connect");
            OutputConnector.Connect();

            Console.WriteLine("[api] wait for connection");
            InputConnector.WaitForConnection();

            Console.WriteLine("[api] Input handler start");
            InputHandler.Start();
        }

        public static void ApiStop()
        {
            OutputConnector.Close();
            InputHandler.Abort();
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
}
