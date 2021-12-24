using Mitigate.Utils;
using System;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class RemovableMediaRestrictrion : Enumeration
    {
        public override string Name => "Removable Media Restriction";
        public override string MitigationType => MitigationTypes.OperatingSystemConfiguration;
        public override string MitigationDescription => @"Disallow or restrict removable media at an organizational policy level if they are not required for business operations.";
        public override string EnumerationDescription => "Checks if removable storage use is disabled";

        public override string[] Techniques => new string[] {
            "T1092",
            "T1052.001"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RegValue = Helper.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\RemovableStorageDevices", "Deny_All");
            yield return new DisabledFeature("Removable storage acccess", RegValue == "1");
        }
    }
}
