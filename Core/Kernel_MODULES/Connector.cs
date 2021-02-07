using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;

using Core.Kernel;
using Core.Kernel.Configurations;
using LoggerLib;

namespace Core.Kernel.Connectors
{
    static class KernelConnectors
    {
        /* OUTPUT CONNECTORS */
        public static NamedPipeClientStream PartitionMon_CommandPipe = new NamedPipeClientStream("PartitionMon.Command");
        public static BinaryWriter PartitionMon_CommandWriter;
        public static Mutex PartitionMon_CommandPipe_Sync = new Mutex();

        public static NamedPipeClientStream VirusesDb_CommandPipe = new NamedPipeClientStream("VirusesDb.CommandPipe");
        public static BinaryWriter VirusesDb_CommandWriter;
        public static Mutex VirusesDb_CommandPipe_Sync = new Mutex();

        public static NamedPipeClientStream ScannerService_Output = new NamedPipeClientStream("ScannerService.Input");
        public static BinaryWriter ScannerService_Writer;
        public static Mutex ScannerService_Output_Sync = new Mutex();



        /* INPUT CONNECTORS */
        public static NamedPipeServerStream Filter_Input = new NamedPipeServerStream("Filter.Output");
        public static BinaryReader Filter_Reader;
        public static Mutex Filter_Input_Sync = new Mutex();

        public static NamedPipeServerStream ScannerService_Input = new NamedPipeServerStream("ScannerService.Output");
        public static BinaryReader ScannerService_Reader;
        public static Mutex ScannerService_Input_Sync = new Mutex();

        /*For API*/
        public static NamedPipeServerStream Api_In = new NamedPipeServerStream("API.Core");
        public static NamedPipeClientStream Api_Out = new NamedPipeClientStream("API.User");

        public static Mutex Api_In_Sync = new Mutex();
        public static Mutex Api_Out_Sync = new Mutex();

        /*For logs*/
        public static LoggerClient Logger = new LoggerClient("Logger.Kernel", "Kernel log");


        public static void InitInputConnections()
        {
            Logger.WriteLine($"[Kernel.Connectors] Wait input connections", LogLevel.WARN);

            Task.Run(() =>
            {
                Filter_Input_Sync.WaitOne();
                {
                    Filter_Input.WaitForConnection();
                    Filter_Reader = new BinaryReader(Filter_Input, KernelInitializator.Config.NamedPipeEncoding);

                    Logger.WriteLine($"[Kernel.Connectors] Filter connected", LogLevel.OK);
                }
                Filter_Input_Sync.ReleaseMutex();
            });

            Task.Run(() =>
            {
                ScannerService_Input_Sync.WaitOne();
                {
                    ScannerService_Input.WaitForConnection();
                    ScannerService_Reader = new BinaryReader(ScannerService_Input, KernelInitializator.Config.NamedPipeEncoding);

                    Logger.WriteLine($"[Kernel.Connectors] Scanner INPUT connected", LogLevel.OK);
                }
                ScannerService_Input_Sync.ReleaseMutex();
            });

            Task.Run(() =>
            {
                Api_In_Sync.WaitOne();
                {
                    Api_In.WaitForConnection();

                    Logger.WriteLine($"[Kernel.Connectors] API INPUT connected", LogLevel.OK);
                }
                Api_In_Sync.ReleaseMutex();
            });
        }

        public static void InitOutputConnections()
        {
            Logger.WriteLine($"[Kernel.Connectors.InitOutputConnections] Wait output connections");

            Task.Run(() =>
            {
                PartitionMon_CommandPipe_Sync.WaitOne();
                {
                    PartitionMon_CommandPipe.Connect();
                    PartitionMon_CommandWriter = new BinaryWriter(PartitionMon_CommandPipe, KernelInitializator.Config.NamedPipeEncoding);

                    Logger.WriteLine($"[Kernel.Connectors] Partition monitor connected", LogLevel.OK);
                }
                PartitionMon_CommandPipe_Sync.ReleaseMutex();
            });

            Task.Run(() =>
            {
                ScannerService_Output_Sync.WaitOne();
                {
                    ScannerService_Output.Connect();
                    ScannerService_Writer = new BinaryWriter(ScannerService_Output, KernelInitializator.Config.NamedPipeEncoding);

                    Logger.WriteLine($"[Kernel.Connectors] Scanner OUTPUT connected", LogLevel.OK);
                }
                ScannerService_Output_Sync.ReleaseMutex();
            });

            Task.Run(() =>
            {
                VirusesDb_CommandPipe_Sync.WaitOne();
                {
                    VirusesDb_CommandPipe.Connect();
                    VirusesDb_CommandWriter = new BinaryWriter(VirusesDb_CommandPipe, KernelInitializator.Config.NamedPipeEncoding);

                    Logger.WriteLine($"[Kernel.Connectors] VirusesDB connected", LogLevel.OK);
                }
                VirusesDb_CommandPipe_Sync.ReleaseMutex();

                Thread.Sleep(100);
            });

            Task.Run(() =>
            {
                Api_Out_Sync.WaitOne();
                {
                    Api_Out.Connect();

                    Logger.WriteLine($"[Kernel.Connectors] API OUT connected", LogLevel.OK);
                }
                Api_Out_Sync.ReleaseMutex();
            });
        }

    }
}