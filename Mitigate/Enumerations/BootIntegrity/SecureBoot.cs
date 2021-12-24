using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class SecureBoot : Enumeration
    {
        public override string Name => "Secure Boot";
        public override string MitigationType => MitigationTypes.BootIntegrity;
        public override string MitigationDescription => "Check the integrity of the existing BIOS and device firmware to determine if it is vulnerable to modification.";
        public override string EnumerationDescription => "Secure Boot Status";

        public override string[] Techniques => new string[] {
            "T1495",
            "T1541.001",
            "T1541.003",
            "T1195.003",
            "T1553.006"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RegPath = @"SYSTEM\CurrentControlSet\Control\SecureBoot\State";
            var SecureBootEnabled = Helper.GetRegValue("HKLM", RegPath, "UEFISecureBootEnabled") == "1";
            yield return new BooleanConfig("Secure Boot", SecureBootEnabled);
        }
    }
}
