using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Mitigate.Enumerations;

namespace Mitigate.Enumerations.AccountUsePolicies
{
    class LockOutPolicies : Enumeration
    {
        public override string Name => "Account lockout policy";
        public override string MitigationType => "Account Use Policies";
        public override string MitigationDescription => "Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed.";
        public override string EnumerationDescription => "Checks if a lockout threshold has been configured";
        public override string[] Techniques => new string[] {
            "T1110",
            "T1110.001",
            "T1110.003",
            "T1110.004"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var PolicyInfo = Interop.Netapi32.GetLockOutPolicy();
            if (PolicyInfo.usrmod3_lockout_threshold > 0)
            {
                yield return new ConfigurationDetected("Lockout Policy Threshold", PolicyInfo.usrmod3_lockout_threshold.ToString());
            }
        }
    }
}
