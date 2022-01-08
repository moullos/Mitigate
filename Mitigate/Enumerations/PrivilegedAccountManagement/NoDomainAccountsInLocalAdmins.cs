using Mitigate.Utils;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;

namespace Mitigate.Enumerations
{
    class NoDomainAccountInLocalAdminGroups : Enumeration
    {
        public override string Name => "No domain accounts in local admins groups";
        public override string MitigationType => MitigationTypes.PrivilegedAccountManagement;
        public override string MitigationDescription => "Do not put user or admin domain accounts in the local administrator groups across systems unless they are tightly controlled, as this is often equivalent to having a local administrator account with the same password on all systems. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.";
        public override string EnumerationDescription => "Checks if any domain accounts exist in local admin groups";

        public override string[] Techniques => new string[] {
            "T1003",
            "T1003.001",
            "T1003.002",
            "T1003.003",
            "T1003.005",
            "T1003.006",
            "T1021.002",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // https://stackoverflow.com/questions/6318611/how-to-get-all-user-account-names-in-xp-vist-7-for-32-or-64-bit-and-any-os
            SecurityIdentifier builtinAdminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
            GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, builtinAdminSid.Value);
            foreach (Principal p in group.Members)
            {
                if (p.Context.ContextType == ContextType.Domain)
                {
                    yield return new GenericResult($"User {p.UserPrincipalName} is part of the local admins group", false);
                    yield break;
                }
            }
            yield return new GenericResult("No domain users in the local admin group", true);
        }
    }
}
