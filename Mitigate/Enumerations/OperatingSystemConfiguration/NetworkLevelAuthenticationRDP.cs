using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations.OperatingSystemConfiguration
{
    class NetworkLevelAuthenticationRDP : Enumeration
    {
        public override string Name => "Network Level Authentication for RDP";
        public override string MitigationType => "Operating System Configuration";
        public override string MitigationDescription => @"Ensure that Network Level Authentication is enabled to force the remote desktop session to authenticate before the session is created and the login screen displayed. It is enabled by default on Windows Vista and later.";
        public override string EnumerationDescription => "Checks if Network Level Authentication of RDP is disabled";

        public override string[] Techniques => new string[] {
            "T1546.008",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RegValue = Helper.GetRegValue("HKLM", @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
            yield return new BooleanConfig("Network Level Authentication for RDP", RegValue != "0");
        }
    }
}
