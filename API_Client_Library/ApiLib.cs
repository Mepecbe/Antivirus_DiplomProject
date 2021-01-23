﻿using System;
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
    /// 
    /// </summary>
    public static class API
    {
        /*=== events ===*/
        public delegate void scanCompetedEvent(ScannedFileInfo File);
        public delegate void scanFoundVirusEvent(VirusFileInfo File);

        public static event scanCompetedEvent onScanCompleted;
        public static event scanFoundVirusEvent onScanFound;

        /*=== Connectors ===*/
        private static NamedPipeServerStream InputConnector = new NamedPipeServerStream("API.User");
        private static NamedPipeClientStream OutputConnector = new NamedPipeClientStream("API.Core");

        /// <summary>
        /// Поток обработки событий
        /// </summary>
        private static Thread InputHandler = new Thread(Handler);

        private static BinaryWriter OutputWriter = new BinaryWriter(OutputConnector);

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

        /*=== ОБРАБОТЧИКИ ===*/
        private static void ScanCompleted(BinaryReader dataReader)
        {
            var kernelId = dataReader.ReadInt32();
            var isVirus = dataReader.ReadBoolean();
            var virusId = dataReader.ReadInt32();
            var file = dataReader.ReadString();

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

        public static void ToQuarantine(int id)
        {
            OutputWriter.Write((byte)1);
            OutputWriter.Write(id);
            OutputWriter.Flush();
        }

        public static void RestoreFile(int id)
        {
            OutputWriter.Write((byte)2);
            OutputWriter.Write(id);
            OutputWriter.Flush();
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
    }
}