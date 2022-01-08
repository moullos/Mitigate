using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class RDPNetworkLevelAuthentication : Enumeration
    {
        public override string Name => "RDP Network Level Authentication";
        public override string MitigationType => MitigationTypes.OperatingSystemConfiguration;
        public override string MitigationDescription => @"To use this technique remotely, an adversary must use it in conjunction with RDP. Ensure that Network Level Authentication is enabled to force the remote desktop session to authenticate before the session is created and the login screen displayed. It is enabled by default on Windows Vista and later.";
        public override string EnumerationDescription => "Checks if RDP Network Level Authentication is set";  

        public override string[] Techniques => new string[] {
            "T1546.008",
            "T1546",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RegPath = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
            var RegKey = "UserAuthentication";
            if (Helper.RegExists("HKLM", RegPath, RegKey))
            {
                var RDPNLAConfig = Helper.GetRegValue("HKLM", RegPath, RegKey);
                yield return new BooleanConfig("RDP Network Level Authentication", RDPNLAConfig == "1");
            }
            else
            {
                // Enabled by default in version later than vista
                //https://stackoverflow.com/questions/2819934/detect-windows-version-in-net
                var Version = SystemUtils.GetOSVersion();
                yield return new BooleanConfig("RDP Network Level Authentication", Version.Major > 5);
            }
        }
    }
}
