using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Kernel.Configurations
{
    public static class Configuration
    {
        public static Encoding NamedPipeEncoding;

        public static void Load()
        {
            NamedPipeEncoding = Encoding.Unicode;
        }
    }
}
