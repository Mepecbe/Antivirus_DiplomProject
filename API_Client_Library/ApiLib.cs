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

    public class VirusFileInfo
    {
        public readonly int kernelId;
        public readonly int virusId;
        public readonly string file;

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

        public static event scanCompetedEvent onScanCompleted;
        public static event scanFoundVirusEvent onScanFound;

        /*=== Connectors ===*/
        private static readonly NamedPipeServerStream InputConnector = new NamedPipeServerStream("API.User");
        private static readonly NamedPipeClientStream OutputConnector = new NamedPipeClientStream("API.Core");

        /// <summary>
        /// Поток обработки событий
        /// </summary>
        private static readonly Thread InputHandler = new Thread(Handler);

        private static readonly BinaryWriter OutputWriter = new BinaryWriter(OutputConnector);
        public static Mutex Writer_sync = new Mutex();


        /// <summary>
        /// Код потока обработчика событий
        /// </summary>
        private static void Handler()
        {
            var reader = new BinaryReader(InputConnector);

            while (true)
            {
                var code = reader.ReadByte();

                switch (code)
                {
                    case 0:
                        {
                            ScanCompleted(reader);
                            break;
                        }

                    case 1:
                        {
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
        /// Очистить очередь сканирования файлов
        /// </summary>
        public static void ClearScanQueue()
        {

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
            InputHandler.Abort();
        }
    }
}
