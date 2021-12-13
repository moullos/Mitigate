using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Principal;
using static Mitigate.Utils.UserUtils;

namespace Mitigate.Enumerations.PasswordPolicies
{
    class NISTGuidelines : Enumeration
    {
        public override string Name => "NIST guidelines";
        public override string MitigationType => "Password Policies";
        public override string MitigationDescription => "Refer to NIST guidelines when creating password policies.";
        public override string EnumerationDescription => "Checks if the Windows password policies are in line with the NIST guidelines";

        public override string[] Techniques => new string[] {
            "T1110.001",
            "T1110.002",
            "T1110.003",
            "T1110.004",
            "T1187",
            "T1003.006",
            "T1003.002",
            "T1003.003",
            "T1003.004",
            "T1003.005",
            "T1021.002",
            "T1550.003",
            "T1078.003"
        
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            using (SamServer server = new SamServer(null, SamServer.SERVER_ACCESS_MASK.SAM_SERVER_ENUMERATE_DOMAINS | SamServer.SERVER_ACCESS_MASK.SAM_SERVER_LOOKUP_DOMAIN))
            {
                var AllDomains = server.EnumerateDomains();
                var HostName = Environment.MachineName.ToString();
                SecurityIdentifier sid;
                SamServer.DOMAIN_PASSWORD_INFORMATION pi;
                sid = server.GetDomainSid(HostName);
                pi = server.GetDomainPasswordInformation(sid);
                yield return new ConfigurationDetected("Max Password Age (NIST guideline <= 60)", pi.MaxPasswordAge.Days.ToString(), pi.MaxPasswordAge.Days <= 60 & pi.MaxPasswordAge.Days != 0);
                yield return new ConfigurationDetected("Password History Length (NIST guideline >= 24)", pi.PasswordHistoryLength.ToString(), pi.PasswordHistoryLength >= 24);
                yield return new BooleanConfig("Password Complexity", pi.PasswordProperties.HasFlag(SamServer.PASSWORD_PROPERTIES.DOMAIN_PASSWORD_COMPLEX));
                yield return new ConfigurationDetected("Min Password Age (NIST guideline >=1)", pi.MinPasswordAge.Days.ToString(), pi.MinPasswordAge.Days >= 1);
                yield return new ConfigurationDetected("Min Password Length (NIST guideline >=14)", pi.MinPasswordLength.ToString(), pi.MinPasswordLength >= 14);
                yield return new BooleanConfig("Not stored in cleartext", !pi.PasswordProperties.HasFlag(SamServer.PASSWORD_PROPERTIES.DOMAIN_PASSWORD_STORE_CLEARTEXT));
            }
        }
    }
}
