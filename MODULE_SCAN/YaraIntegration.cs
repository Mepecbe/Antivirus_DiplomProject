using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;

using MODULE__SCAN;
using LoggerLib;
using YaraSharp;
using Alphaleonis;

namespace MODULE__SCAN.Yara
{
    static class YaraIntegration
    {
        public static YSInstance Instance;
        public static YSContext Context;
        public static YSCompiler Compiler;

        public static YSRules Rules;
        public static YSReport Errors;
        public static YSReport Warnings;

        private static string[] skipExtentions = new string[] { /*".db", ".toc", ".sp", ".sb", ".dll"*/ };

        public static void Init()
        {
            Connector.Logger.WriteLine("[YaraIntegration.Init] Start");

            Instance = new YSInstance();

            Dictionary<string, object> externals = new Dictionary<string, object>()
            {
                { "filename", string.Empty },
                { "filepath", string.Empty },
                { "extension", string.Empty }
            };

            Connector.Logger.WriteLine("[YaraIntegration.Init] Загрука YARA правил");

            List<string> ruleFilenames = Directory.GetFiles(MODULE__SCAN.Configuration.YaraRulesDir, "*.yar", MODULE__SCAN.Configuration.YaraRulesSearchOption).ToList();
            Connector.Logger.WriteLine($"[YaraIntegration.Init] Загружено {ruleFilenames.Count} файлов ");

            Context = new YSContext();
            Compiler = Instance.CompileFromFiles(ruleFilenames, externals);

            Rules = Compiler.GetRules();
            Errors = Compiler.GetErrors();
            Warnings = Compiler.GetWarnings();

            var ErrDump = Errors.Dump();
            var WrnDump = Warnings.Dump();

            foreach (var key in ErrDump)
            {
                Connector.Logger.WriteLine($"[YaraIntegration.Init] Error!");
            }

            foreach (var key in WrnDump)
            {
                Connector.Logger.WriteLine($"[YaraIntegration.Init] Warning!");
            }

            Connector.Logger.WriteLine($"[YaraIntegration.Init] Загрузка завершена");
        }

        public static List<YSMatches> GetCheckResult(string path)
        {
            foreach (string ext in skipExtentions)
            {
                if (path.Contains(ext))
                {
                    return new List<YSMatches>();
                }
            }

            List<YSMatches> Matches = new List<YSMatches>();

            try
            {
                Matches = Instance.ScanFile(path, Rules,
                        new Dictionary<string, object>()
                        {
                    { "filename",  Alphaleonis.Win32.Filesystem.Path.GetFileName(path) },
                    { "filepath",  Alphaleonis.Win32.Filesystem.Path.GetFullPath(path) },
                    { "extension", Alphaleonis.Win32.Filesystem.Path.GetExtension(path) }
                        },
                        0);
            }
            catch
            {

            }

            var matches = new List<YSMatches>();

            foreach (YSMatches Match in Matches)
            {
                if (Match.Rule.Identifier == "UPX")
                {
                    continue;
                }

                Connector.Logger.WriteLine("[Yara.check] ВНИМАНИЕ! СОВПАДЕНИЕ! ->" + Match.Rule.Identifier, LogLevel.WARN);
                matches.Add(Match);
            }

            return matches;
        }

        public static bool CheckFile(string path)
        {
            if (GetCheckResult(path).Count > 0)
            {
                return true;
            }

            return false;
        }
    }
}
