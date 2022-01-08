using Mitigate.Utils;
using System.Collections.Generic;
using System.Linq;

namespace Mitigate.Enumerations
{
    class HardenedTokenPermissions : Enumeration
    {
        public override string Name => "Limit token permissions";
        public override string MitigationType => MitigationTypes.PrivilegedAccountManagement;
        public override string MitigationDescription => "Limit permissions so that users and user groups cannot create tokens. This setting should be defined for the local system account only. GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Create a token object. [1] Also define who can create a process level token to only the local and network service through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Replace a process level token.";
        public override string EnumerationDescription => "Checks if the specified user has the necessary permissions to create tokens";

        public override string[] Techniques => new string[] {
            "T1134",
            "T1134.001",
            "T1134.002"


        
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            List<string> AccountSIDs = UserUtils.GetUsersWithPrivilege("SeCreateTokenPrivilege");
            if (AccountSIDs.Count == 0)
            {
                // Only Local Admins have the permission
                yield return new GenericResult("Only administrators can create tokens.", true);
            }
            else
            {
                bool AccountsInInterestingSIDs = !AccountSIDs.Intersect(context.UserToCheckSIDs).Any();
                yield return new DisabledFeature($"{context.UserToCheck} cannot create tokens", !AccountsInInterestingSIDs);
     
            }
        }
    }
}
