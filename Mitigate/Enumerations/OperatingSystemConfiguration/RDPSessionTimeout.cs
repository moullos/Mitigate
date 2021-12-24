using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class RDPSessionTimeout : Enumeration
    {
        public override string Name => "RDP sessions timeout";
        public override string MitigationType => MitigationTypes.OperatingSystemConfiguration;
        public override string MitigationDescription => @"Change GPOs to define shorter timeouts sessions and maximum amount of time any single session can be active. Change GPOs to specify the maximum amount of time that a disconnected session stays active on the RD session host server.";
        public override string EnumerationDescription => "Checks if RDP sessions timeout limits are set";

        public override string[] Techniques => new string[] {
            "T1021.001",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RegPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
            var MaxIdleTimeStr = Helper.GetRegValue("HKLM", RegPath, "MaxIdleTime");
            var MaxConnectionTimeStr = Helper.GetRegValue("HKLM", RegPath, "MaxConnectionTime");
            if (int.TryParse(MaxIdleTimeStr, out var MaxIdleTimeInt))
            {
                yield return new ConfigurationDetected("RDP Maximum idle time", MaxIdleTimeStr, MaxIdleTimeInt <= 900000 && MaxIdleTimeInt != 0, "<= 900000 (15 mins)");
            }
            if (int.TryParse(MaxConnectionTimeStr, out var MaxConnectionTimeInt))
            {
                yield return new ConfigurationDetected("RDP Maximum Session time", MaxConnectionTimeStr, MaxConnectionTimeInt <= 28800000 && MaxConnectionTimeInt != 0, "<= 28800000 (8 hours)");
            }


        }
    }
}
