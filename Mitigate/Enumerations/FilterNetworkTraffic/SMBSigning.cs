using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class SMBSigning : Enumeration
    {
        public override string Name => "Enforce SMB Signing";
        public override string MitigationType => MitigationTypes.FilterNetworkTraffic;
        public override string MitigationDescription => @"Use host-based security software to block LLMNR/NetBIOS traffic. Enabling SMB Signing can stop NTLMv2 relay attacks.";
        public override string EnumerationDescription => "Checks SMB signing enforcement";

        public override string[] Techniques => new string[] {
            "T1557",
            "T1557.001"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            //https://www.stigviewer.com/stig/windows_server_2016/2018-03-07/finding/V-73653
            var RegPath = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\";
            var RegKey = "RequireSecuritySignature";
            var SMBSigningConfig = Helper.GetRegValue("HKLM", RegPath, RegKey);
            yield return new BooleanConfig("SMB signing", SMBSigningConfig == "1");
        }
    }
}
