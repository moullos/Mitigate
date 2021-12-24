using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class NetworkCachedCredsDisabled : Enumeration
    {
        public override string Name => "NetworkCachedCredsDisabled";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "Consider enabling the “Network access: Do not allow storage of passwords and credentials for network authentication” setting that will prevent network credentials from being stored by the Credential Manager.";
        public override string EnumerationDescription => "Checks if the storage of password and credentials for network authentication is disable";

        public override string[] Techniques => new string[] {
            "T1555.004"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // https://www.stigviewer.com/stig/windows_server_2016/2018-03-07/finding/V-73671
            var RegValue = Helper.GetRegValue("HKML", @"\SYSTEM\CurrentControlSet\Control\Lsa\", "DisableDomainCreds");
            yield return new DisabledFeature("Storage of password and credentials for network authentication", RegValue == "1");
        }
    }
}
