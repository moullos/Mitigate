using Mitigate.Utils;
using System.Collections.Generic;
using System.Linq;

namespace Mitigate.Enumerations
{
    class NoAdministratorsInRDPUsers : Enumeration
    {
        public override string Name => "Remove the local administrators group from RDP";
        public override string MitigationType => MitigationTypes.PrivilegedAccountManagement;
        public override string MitigationDescription => "Consider removing the local Administrators group from the list of groups allowed to log in through RDP";
        public override string EnumerationDescription => "Checks if the local admin groups is in the list of groups allowed to RDP on the machine";

        public override string[] Techniques => new string[] {
            "T1563",
            "T1563.002",
            "T1021.002"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            List<string> AllowedSIDs = UserUtils.GetUsersWithPrivilege("SeRemoteInteractiveLogonRight");
            List<string> BlockedSIDs = UserUtils.GetUsersWithPrivilege("SeDenyRemoteInteractiveLogonRight");
            yield return new BooleanConfig("No admins in can be allowed to log in through RDP",!UserUtils.IsAdmin(AllowedSIDs) || UserUtils.IsAdmin(BlockedSIDs));
        }
    }
}
