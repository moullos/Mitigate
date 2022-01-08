using Mitigate.Utils;
using System.Collections.Generic;
using System.Linq;

namespace Mitigate.Enumerations
{
    class PassTheHashMitigations : Enumeration
    {
        public override string Name => "Enable pass the hash mitigations to apply UAC restrictions to local accounts on network logon";
        public override string MitigationType => MitigationTypes.UserAccountControl;
        public override string MitigationDescription => @"Enable pass the hash mitigations to apply UAC restrictions to local accounts on network logon. The associated Registry key is located HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy. Through GPO: Computer Configuration > [Policies] > Administrative Templates > SCM: Pass the Hash Mitigations: Apply UAC restrictions to local accounts on network logons.";
        public override string EnumerationDescription => "Checks for pass the hash mitigations";

        public override string[] Techniques => new string[] {
            "T1550.002"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // PtH Mitigation Settings
            var RegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            var RegName = @"LocalAccountTokenFilterPolicy";
            var PashTheHashMitigationValue = Helper.GetRegValue("HKLM", RegPath, RegName);
            // Value being = 0 is enabled -> https://admx.help/?Category=SecurityBaseline&Policy=Microsoft.Policies.PtH::Pol_PtH_LATFP
            yield return new BooleanConfig("Pass the hash mitigation for UAC", PashTheHashMitigationValue == "0");
        }
    }
}
