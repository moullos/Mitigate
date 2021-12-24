using Mitigate.Utils;
using System;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class NetworkShareDiscoveryPrevention : Enumeration
    {
        public override string Name => "Network Share Discovery Prevention";
        public override string MitigationType => MitigationTypes.OperatingSystemConfiguration;
        public override string MitigationDescription => @"Enable Windows Group Policy 'Do Not Allow Anonymous Enumeration of SAM Accounts and Shares' security setting to limit users who can enumerate network shares.";
        public override string EnumerationDescription => "Checks if the anonymous enumeration of SAM accounts is restricted";

        public override string[] Techniques => new string[] {
            "T1135",

        
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            //https://www.stigviewer.com/stig/windows_2008_member_server/2018-03-07/finding/V-1093
            var RegValue = Helper.GetRegValue("HKLM", @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous");
            yield return new DisabledFeature("Anonymous Enumeration of SAM accounts", RegValue == "1");

        }
    }
}
