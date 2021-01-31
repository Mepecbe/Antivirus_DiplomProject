﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;

using LoggerLib;

namespace Core.Kernel.Connectors
{
    static class KernelConnectors
    {
        /* OUTPUT CONNECTORS */
        public static NamedPipeClientStream PartitionMon_CommandPipe = new NamedPipeClientStream("PartitionMon.Command");
        public static Mutex PartitionMon_CommandPipe_Sync = new Mutex();

        public static NamedPipeClientStream VirusesDb_CommandPipe = new NamedPipeClientStream("VirusesDb.CommandPipe");
        public static Mutex VirusesDb_CommandPipe_Sync = new Mutex();

        public static NamedPipeClientStream ScannerService_Output = new NamedPipeClientStream("ScannerService.Input");
        public static Mutex ScannerService_Output_Sync = new Mutex();



        /* INPUT CONNECTORS */
        public static NamedPipeServerStream Filter_Input = new NamedPipeServerStream("Filter.Output");
        public static Mutex Filter_Input_Sync = new Mutex();

        public static NamedPipeServerStream ScannerService_Input = new NamedPipeServerStream("ScannerService.Output");
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
#if DEBUG
            Console.WriteLine($"[Kernel.Connectors.InitInputConnections] Wait input connections");
#endif
            Task.Run(() =>
            {
                Filter_Input_Sync.WaitOne();
                Filter_Input.WaitForConnection();
                Filter_Input_Sync.ReleaseMutex();
            });

            Task.Run(() =>
            {
                ScannerService_Input_Sync.WaitOne();
                ScannerService_Input.WaitForConnection();
                ScannerService_Input_Sync.ReleaseMutex();
            });

            Task.Run(() =>
            {
                Api_In_Sync.WaitOne();
                Api_In.WaitForConnection();
                Api_In_Sync.ReleaseMutex();
            });
        }

        public static void InitOutputConnections()
        {
            Logger.WriteLine($"[Kernel.Connectors.InitOutputConnections] Wait output connections");

            Task.Run(() =>
            {
                PartitionMon_CommandPipe_Sync.WaitOne();
                PartitionMon_CommandPipe.Connect();
                PartitionMon_CommandPipe_Sync.ReleaseMutex();
            });

            Task.Run(() =>
            {
                ScannerService_Output_Sync.WaitOne();
                ScannerService_Output.Connect();
                ScannerService_Output_Sync.ReleaseMutex();
            });

            Task.Run(() =>
            {
                VirusesDb_CommandPipe_Sync.WaitOne();
                VirusesDb_CommandPipe.Connect();
                VirusesDb_CommandPipe_Sync.ReleaseMutex();

                StreamWriter writer = new StreamWriter(VirusesDb_CommandPipe, Encoding.Unicode) { AutoFlush = true };

                Thread.Sleep(100);
                writer.WriteLine("/upload_to_scanner");
            });

            Task.Run(() =>
            {
                Api_Out_Sync.WaitOne();
                Api_Out.Connect();
                Api_Out_Sync.ReleaseMutex();
            });
        }

    }
}