using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;

using API_Client_Library;

namespace API_Client
{
    class Program
    {
        static void Main(string[] args)
        {
            API.Init();
            API.onScanCompleted += (ScannedFileInfo File) =>
            {
                Console.WriteLine("[API CLIENT] SCAN COMPLETED ->" + File.file);
            };
        }
    }
}
