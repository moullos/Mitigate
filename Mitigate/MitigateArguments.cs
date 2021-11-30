using System;
using System.Linq;

namespace Mitigate
{

    // The following class was adapted from Seatbelt's ArgumentParse and it is subject to the SeatBelt license
    // https://github.com/GhostPack/Seatbelt/blob/master/LICENSE

    public class MitigateArguments
    {

        private string[] Arguments { get; set; }
        public bool ShowUnmitigatableTechnique { get; private set; }
        public bool ExportCoverage { get; private set; }
        public bool Verbose { get; private set; }
        public bool Full { get; private set; }
        public bool Debug { get; private set; }
        public string OutFile { get; private set; }
        public string Username { get; private set; }
        public string GenerateDocumentation { get; private set; }
        public string GenerateTracker { get; private set; }


        public MitigateArguments(string[] args)
        {
            Arguments = args;
            Parse();
        }

        public void Parse()
        {
            OutFile = ParseAndRemoveKeyValueArgument("-OutFile", false);
            ShowUnmitigatableTechnique = ParseAndRemoveSwitchArgument("-ShowUnmitigateableTechniques", true);
            ExportCoverage = ParseAndRemoveSwitchArgument("-ExportCoverage", false);
            Verbose = ParseAndRemoveSwitchArgument("-Verbose", false);
            Username = ParseAndRemoveKeyValueArgument("-Username");
            Full = ParseAndRemoveSwitchArgument("-Full", false);
            Debug = ParseAndRemoveSwitchArgument("-Debug", false);
            GenerateDocumentation = ParseAndRemoveKeyValueArgument("-GenerateDocumentation");
            GenerateTracker = ParseAndRemoveKeyValueArgument("-GenerateTracker");
        }

        private bool ParseAndRemoveSwitchArgument(string key, bool defaultValue)
        {
            if (Arguments.Contains(key, StringComparer.CurrentCultureIgnoreCase))
            {
                Arguments = Arguments.Where(c => c.ToLower() != key.ToLower()).ToArray();
                return true;
            }

            return defaultValue;
        }

        private string ParseAndRemoveKeyValueArgument(string key, bool optional = true)
        {
            var arg = Arguments.FirstOrDefault(
                c => c.ToLower().StartsWith($"{key.ToLower()}=")
            );

            if (string.IsNullOrEmpty(arg))
                if (optional)
                    return String.Empty;
                else throw new Exception($"{key} is a required key value argument");

            try
            {
                var value = arg.Substring(arg.IndexOf('=') + 1);
                Arguments = Arguments.Where(c => !c.ToLower().StartsWith(key.ToLower())).ToArray();
                return value;
            }
            catch (Exception e)
            {
                throw new Exception($"Error parsing argument \"{key}\": {e}");
            }
        }
        public static void PrintUsage()
        {

            Console.WriteLine("Usage: Mitigate.exe");
            Console.WriteLine("       -OutFile=<FileName> : The file name of the resulting navigator layer file. Can be imported into the ATT&CK Navigator for visualisation");
            Console.WriteLine("       -UserName=<username> : A user to perform all the least privilege checks for. Default is the last logged in user");
            Console.WriteLine("       -Verbose : Increases the verbosity of the output for some of the enumerations");
            Console.WriteLine("       -ExportCoverage : Outputs a navigator layer file just capturing the technique coverage of the implemented enumerations");
            Console.WriteLine("       -Full : Performs more detailed COM and WMI permissions enumerations");
        }
    }
}
