using Mitigate.Utils;
using System;
using System.Collections.Generic;

namespace Mitigate.Enumerations.OperatingSystemConfiguration
{
    class DisableNTLM : Enumeration
    {
        public override string Name => "Disable NTLM";
        public override string MitigationType => "Operating System Configuration";
        public override string MitigationDescription => @"Consider disabling or restricting NTLM.";
        public override string EnumerationDescription => "Checks if both inbound and outbound NTLM is disabled";

        public override string[] Techniques => new string[] {
            "T1003.001",
            "T1003.002"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            //Restricting Outbound NTLM traffic
            var RegValue = Helper.GetRegValue("HKLM", @"System\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictSendingNTLMTraffic");
            yield return new DisabledFeature("Outbound NTLM traffic", RegValue == "2");

            // Restricting Inbound NTLM traffic
            RegValue = Helper.GetRegValue("HKLM", @"System\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictReceivingNTLMTraffic");
            yield return new DisabledFeature("Inbound NTLM traffic", RegValue == "2");

        }
    }
}
