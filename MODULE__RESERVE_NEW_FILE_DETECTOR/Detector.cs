using System;
using System.IO;
using System.IO.Pipes;

namespace MODULE__RESERVE_NEW_FILE_DETECTOR
{
    public static class ReserveDetector
    {
        private const string PipeName = "FileNamePipe";
    }

    public static class Initializator
    {
        public static byte EntryPoint()
        {
            return 0;
        }
    }
}
