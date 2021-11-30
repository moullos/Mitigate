using Mitigate.Utils;
using System;
using System.Collections.Generic;

namespace Mitigate.Enumerations.OperatingSystemConfiguration
{
    class DisableWDigest : Enumeration
    {
        public override string Name => "Disable WDigest";
        public override string MitigationType => "Operating System Configuration";
        public override string MitigationDescription => @"Consider disabling or restricting WDigest.";
        public override string EnumerationDescription => "Checks if WDigest is disabled";

        public override string[] Techniques => new string[] {
            "T1003.001",
            "T1003.002"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RegValue = Helper.GetRegValue("HKLM", @"System\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential");
            yield return new DisabledFeature("WDigest password being stored in memory", RegValue != "0");

        }
    }
}
