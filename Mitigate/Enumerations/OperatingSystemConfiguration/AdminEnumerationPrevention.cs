using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class AdminEnumerationPrevention : Enumeration
    {
        public override string Name => "Admin Enumeration Prevention";
        public override string MitigationType => MitigationTypes.OperatingSystemConfiguration;
        public override string MitigationDescription => @"Prevent administrator accounts from being enumerated when an application is elevating through UAC since it can lead to the disclosure of account names. The Registry key is located HKLM\ SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators. It can be disabled through GPO: Computer Configuration > [Policies] > Administrative Templates > Windows Components > Credential User Interface: E numerate administrator accounts on elevation";
        public override string EnumerationDescription => "Checks if account enumeration on UAC is disabled";
        public override string[] Techniques => new string[] {
            "T1087.001",
            "T1087.002",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // Disabled by default
            var RegValue = Helper.GetRegValue("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI", "EnumerateAdministrators");
            yield return new DisabledFeature("Admin account enumeration on UAC", RegValue=="" || RegValue=="0") ;
        }
    }
}
