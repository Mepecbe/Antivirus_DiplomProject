using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.IO.Pipes;

namespace LoggerLib
{
    public enum LogLevel
    {
        WARN,
        INFO,
        ERROR
    }

    public class LoggerClient
    {
        public NamedPipeClientStream outputPipe;
        public BinaryWriter writer;
        public string Name { get; private set; }
        public string PipeName { get; private set; }

        public LoggerClient(string pipeName, string loggerName)
        {
            this.Name = loggerName;
            this.PipeName = pipeName;

            outputPipe = new NamedPipeClientStream(".", pipeName, PipeDirection.Out);
        }

        public void ToOutput(string message, LogLevel level)
        {
#if DEBUG
            if (outputPipe.IsConnected)
            {
                this.writer.Write($"{(byte)level} {message}");
            }
#endif
        }

        public void WriteLine(string message, LogLevel level = LogLevel.INFO)
        {
#if DEBUG
            if (outputPipe.IsConnected)
            {
                this.writer.Write($"{(byte)level} {message}");
                outputPipe.WaitForPipeDrain();
            }
#endif
        }


        /// <summary>
        /// Инициализация логгера
        /// </summary>
        public void Init()
        {
            Console.WriteLine($"[LoggerLib] Wait connect to {PipeName}");
            outputPipe.Connect();
            writer = new BinaryWriter(outputPipe);
            Console.WriteLine($"[LoggerLib] Connected to {PipeName}");
        }
    }
}
