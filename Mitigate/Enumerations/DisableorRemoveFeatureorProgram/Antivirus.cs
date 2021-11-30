
using System;
using System.Collections.Generic;
using System.Management;

namespace Mitigate.Enumerations.DisableorRemoveFeatureorProgram
{
    internal class WakeUpOnLanDisabled : Enumeration
    {
        public override string Name => "Wake Up On Lan Disabled";
        public override string MitigationType => "Disable or Remove Feature or Program";
        public override string MitigationDescription => "Anti-virus can be used to automatically quarantine suspicious files.";
        public override string EnumerationDescription => "Checks if any antivirus is registered (WMI-based)";

        public override string[] Techniques => new string[] {
            "T1059",
            };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // https://stackoverflow.com/questions/1331887/detect-antivirus-on-windows-using-c-sharp and winPEAS
            string wmipathstr = @"\\" + Environment.MachineName + @"\root\GUID_NDIS_PM_CAPABILITIES";

            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT * FROM AntivirusProduct");
            ManagementObjectCollection instances = searcher.Get();
                        
            foreach (ManagementObject instance in instances)
            {
                yield return new ToolDetected((string)instance["displayName"]);
            }
        }
    }
}
