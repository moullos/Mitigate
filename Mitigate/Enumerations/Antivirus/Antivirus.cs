using System;
using System.Collections.Generic;
using System.Management;

namespace Mitigate.Enumerations
{
    internal class Antivirus : Enumeration
    {
        public override string Name => "Antivirus";
        public override string MitigationType => MitigationTypes.AntivirusAntimalware;
        public override string MitigationDescription => "Anti-virus can be used to automatically quarantine suspicious files.";
        public override string EnumerationDescription => "Checks if any antivirus is registered (WMI-based)";

        public override string[] Techniques => new string[] {
            "T1059",
            "T1059.001",
            "T1059.005",
            "T1059.006",
            "T1027.002",
            "T1566",
            "T1566.001",
            "T1566.003",
            "T1221"
            };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // https://stackoverflow.com/questions/1331887/detect-antivirus-on-windows-using-c-sharp and winPEAS
            string wmipathstr = @"\\" + Environment.MachineName + @"\root\SecurityCenter2";

            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT * FROM AntivirusProduct");
            ManagementObjectCollection instances = searcher.Get();
                        
            foreach (ManagementObject instance in instances)
            {
                yield return new ToolDetected((string)instance["displayName"]);
            }
        }
    }
}
