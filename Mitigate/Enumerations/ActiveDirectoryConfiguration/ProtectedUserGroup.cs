using Mitigate.Utils;
using System.Collections.Generic;
using System.Linq;

namespace Mitigate.Enumerations
{
    class ProtectedUserGroup : Enumeration
    {
        public override string Name => "Protected Users Group";
        public override string MitigationType => MitigationTypes.ActiveDirectoryConfiguration;
        public override string MitigationDescription => "Consider adding users to the 'Protected Users' Active Directory security group. This can help limit the caching of users' plaintext credentials.	";
        public override string EnumerationDescription => "Checks if the user last logged in the device is part of the Protected Users group. Use the '-User' flag if you want the check to run for another user";

        public override string[] Techniques => new string[] {
            "T1003.005"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            if (context.UserToCheck.ContextType == System.DirectoryServices.AccountManagement.ContextType.Machine)
            {
                yield return new NotApplicable($"{context.UserToCheck.SamAccountName} is not a domain user");
                yield break;
            }
            IEnumerable<string> Groups = UserUtils.GetGroups(context.UserToCheck);
            // From https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group
            // Protected user group SID: S-1-5-21-<domain>-525
            var ProtectedUsersGroup = Groups.Where(o => o.StartsWith("S-1-5-21-") && o.EndsWith("-525"));
            if (ProtectedUsersGroup.Count() == 1)
            {
                yield return new BooleanConfig($"User {context.UserToCheck} in the Protected Users Group", true);
            }
            else if (ProtectedUsersGroup.Count() == 0)
            {
                yield return new BooleanConfig($"User {context.UserToCheck} in the Protected Users Group", false);
            }
        }

    }
}
