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

namespace Core.Kernel.API
{
    static class API
    {
        private static Thread RequestHandler = new Thread(Handler);

        private static NamedPipeClientStream UserOutputConnector;
        private static Mutex API_Out_sync;

        private static NamedPipeServerStream UserInputConnector;
        private static Mutex API_In_sync;

        private static BinaryWriter Out_writer;


        private static void Handler()
        {
            var binaryReader = new BinaryReader(UserInputConnector);
            var stringReader = new StreamReader(UserInputConnector);
            Out_writer = new BinaryWriter(UserOutputConnector);

#if DEBUG
            Console.WriteLine("[API] Init success");
#endif

            while (true)
            {
                KernelConnectors.Api_In_Sync.WaitOne();

                {
                    var code = binaryReader.ReadByte();

#if DEBUG
                    Console.WriteLine($"[API] Request, code {code}");
#endif

                    switch (code)
                    {
                        //Запрос на проверку файла
                        case 0:
                            {
                                var file = stringReader.ReadLine();

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

                        //Запрос на удаление файла из карантина
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
                                ScanTasks.Add(file);
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

        private static void ScanCompleted(int id, bool found, int virusId, string file)
        {
            API_Out_sync.WaitOne();
            {
                //Идентификатор 
                Out_writer.Write((byte)0);

                Out_writer.Write(id);
                Out_writer.Write(found);
                Out_writer.Write(virusId);
                Out_writer.Write(file);
                Out_writer.Flush();
            }
            API_Out_sync.ReleaseMutex();
        }

        /// <summary>
        /// Переместить файл в карантин
        /// </summary>
        /// <param name="id"></param>
        private static void ToQuarantine(int id)
        {
            var virusInfo = ScanModule.FoundVirusesManager.getInfo(id);
            Quarantine.Quarantine.MoveVirusToQuarantine(id);
        }

        /// <summary>
        /// Восстановить файл
        /// </summary>
        /// <param name="id"></param>
        private static void Restore(int id)
        {
            Quarantine.Quarantine.Restore(id);
        }

        /// <summary>
        /// Удалить файл, где бы он не находился(в карантине/на диске)
        /// </summary>
        /// <param name="id"></param>
        private static void Delete(int id)
        {
#warning Реализовать!
        }

        private static void getVirusInfo(int id)
        {
            var virusInfo = ScanModule.FoundVirusesManager.getInfo(id);

            if(virusInfo == null)
            {
                return;
            }

            API_Out_sync.WaitOne();
            {
                Out_writer.Write((byte)1);
                Out_writer.Write(virusInfo.file);
                Out_writer.Write(virusInfo.VirusId);
                Out_writer.Write(virusInfo.inQuarantine);
                Out_writer.Write(virusInfo.fileInQuarantine);
                Out_writer.Flush();
            }
            API_Out_sync.ReleaseMutex();
        }

        private static void getAllVirusesInfo()
        {
            API_Out_sync.WaitOne();
            {
                foreach(VirusInfo virusInfo in FoundVirusesManager.getAllViruses())
                {
                    Out_writer.Write((byte)1);
                    Out_writer.Write(virusInfo.file);
                    Out_writer.Write(virusInfo.VirusId);
                    Out_writer.Write(virusInfo.inQuarantine);
                    Out_writer.Write(virusInfo.fileInQuarantine);
                    Out_writer.Flush();
                }
            }
            API_Out_sync.ReleaseMutex();
        }


        public static void Init()
        {
            UserOutputConnector = KernelConnectors.Api_Out;
            UserInputConnector = KernelConnectors.Api_In;

            API_In_sync = KernelConnectors.Api_In_Sync;
            API_Out_sync = KernelConnectors.Api_Out_Sync;

            ScannerResponseHandler.onScanCompleted += ScanCompleted;

            RequestHandler.Start();
        }
    }
}
