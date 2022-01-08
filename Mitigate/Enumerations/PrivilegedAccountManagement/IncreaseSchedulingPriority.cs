using Mitigate.Utils;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;

namespace Mitigate.Enumerations
{
    class IncreaseSchedulingPriority : Enumeration
    {
        public override string Name => "Increase Scheduling Priority Least Privilege";
        public override string MitigationType => MitigationTypes.PrivilegedAccountManagement;
        public override string MitigationDescription => "Configure the Increase Scheduling Priority option to only allow the Administrators group the rights to schedule a priority process. This can be can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Increase scheduling priority.";
        public override string EnumerationDescription => "Checks if the Increase Scheduling Priority privilege is only assigned to local admins";

        public override string[] Techniques => new string[] {
            "T1053",
            "T1053.002",
            "T1053.005"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            SecurityIdentifier builtinAdminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            List<string> AllowedSIDs = UserUtils.GetUsersWithPrivilege("SeRemoteInteractiveLogonRight");
            if (AllowedSIDs.Count == 1)
            {
                if (builtinAdminSid.ToString().Equals(AllowedSIDs.First()))
                {
                    yield return new BooleanConfig("Only local admins are allowed to increase scheduling priority", true);
                    yield break;
                }
            }
            yield return new BooleanConfig("Only local admins are allowed to increase scheduling priority", false);
        }
    }
}
