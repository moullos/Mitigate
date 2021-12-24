using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;

namespace Mitigate.Enumerations
{
    public class Context
    {
        public UserPrincipal UserToCheck { get; }
        public MitigateArguments Arguments { get; }
        public bool IsDomainJoined { get; }
        public List<string> UserToCheckSIDs { get; }
        public Context(UserPrincipal user2Check,List<string> user2CheckSIDs, MitigateArguments arguments, bool isDomainJoined)
        {
            UserToCheck = user2Check;
            UserToCheckSIDs = user2CheckSIDs;
            Arguments = arguments;
            IsDomainJoined = isDomainJoined;
        }
    }
}
