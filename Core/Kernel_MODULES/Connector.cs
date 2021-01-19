using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;

namespace Core.Kernel.Connectors
{
    static class Connectors
    {
        public static NamedPipeClientStream PartitionMon_CommandPipe = new NamedPipeClientStream("PartitionMon.Command");
        public static NamedPipeClientStream VirusesDb_CommandPipe = new NamedPipeClientStream("VirusesDb.CommandPipe");
        public static NamedPipeClientStream ScannerService_Output = new NamedPipeClientStream("ScannerService.Input");

        public static NamedPipeServerStream Filter_Input = new NamedPipeServerStream("Filter.Output");
        public static NamedPipeServerStream ScannerService_Input = new NamedPipeServerStream("ScannerService.Output");


        public static void InitInputConnections()
        {
#if DEBUG
            Console.WriteLine($"[Kernel.Connectors.InitInputConnections] Wait input connections");
#endif
            Task.Run(() =>
            {
                Filter_Input.WaitForConnection();
            });

            Task.Run(() =>
            {
                ScannerService_Input.WaitForConnection();
            });
        }

        public static void InitOutputConnections()
        {
#if DEBUG
            Console.WriteLine($"[Kernel.Connectors.InitOutputConnections] Wait output connections");
#endif
            Task.Run(() =>
            {
                PartitionMon_CommandPipe.Connect();
            });

            Task.Run(() =>
            {
                ScannerService_Output.Connect();
            });

            Task.Run(() =>
            {
                VirusesDb_CommandPipe.Connect();
                StreamWriter writer = new StreamWriter(VirusesDb_CommandPipe, Encoding.Unicode) { AutoFlush = true };

                Thread.Sleep(1000);
                writer.WriteLine("/upload_to_scanner");
            });
        }

    }
}
