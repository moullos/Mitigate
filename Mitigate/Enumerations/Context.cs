using System.DirectoryServices.AccountManagement;

namespace Mitigate.Enumerations
{
    public class Context
    {
        public UserPrincipal UserToCheck { get; }
        public MitigateArguments Arguments { get; }
        public bool IsDomainJoined { get; }
        public Context(UserPrincipal user2Check, MitigateArguments arguments, bool isDomainJoined)
        {
            UserToCheck = user2Check;
            Arguments = arguments;
            IsDomainJoined = isDomainJoined;
        }
    }
}
