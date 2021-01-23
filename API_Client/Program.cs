using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;

using API_Client_Library;

namespace API_Client
{
    class Program
    {
        public static void completedScan(ScannedFileInfo File)
        {
            Console.WriteLine($"[Program] completed scan {File.file}");
        }

        public static void scanFoundVirus(VirusFileInfo File)
        {
            Console.WriteLine($"[Program] found virus {File.file}, id {File.kernelId}, virus id {File.virusId}");

            new Task(() => {
                Thread.Sleep(3000);
                Console.WriteLine("CALL TO QUARANTINE");
                API.ToQuarantine(File.kernelId);
            }).Start();


            new Task(() => {
                Thread.Sleep(10000);
                Console.WriteLine("CALL RESTORE");
                API.RestoreFile(File.kernelId);
            }).Start();
        }

        static void Main(string[] args)
        {
            API.onScanCompleted += completedScan;
            API.onScanFound += scanFoundVirus;

            API.Init();

        }
    }
}
