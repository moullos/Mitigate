using Mitigate.Utils;
using System;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class CachedDomainCredsLimit : Enumeration
    {
        public override string Name => "Limit the number of cached credentials";
        public override string MitigationType => MitigationTypes.OperatingSystemConfiguration;
        public override string MitigationDescription => @"Consider limiting the number of cached credentials (HKLM\SOFTWARE\Microsoft\Windows NT\Current Version\Winlogon\cachedlogonscountvalue)";
        public override string EnumerationDescription => "Checks if the cached credentials limit is less than 10";

        public override string[] Techniques => new string[] {
            "T1003.005"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            if (!context.IsDomainJoined)
            {
                yield return new NotApplicable("Mitigation only applied to domain-joined devices");
            }
            else
            {
                var RegValue = Helper.GetRegValue("HKLM", @"SOFTWARE\Microsoft\Windows NT\Current Version\Winlogon", "cachedlogonscountvalue");
                if (int.TryParse(RegValue, out var limit))
                {
                    yield return new ConfigurationDetected("Cached credentials limit", RegValue, limit <= 10);
                }
            }


        }
    }
}
