using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations
{
    class CredentialGuard : Enumeration
    {
        public override string Name => "Credential Guard";
        public override string MitigationType => MitigationTypes.CredentialAccessProtection;
        public override string MitigationDescription => "On Windows 10 and Server 2016, enable Windows Defender Credential Guard to run lsass.exe in an isolated virtualized environment without any device drivers.";
        public override string EnumerationDescription => "Credential Guard Status";

        public override string[] Techniques => new string[] {
            "T1547.008",
            "T1003.001",
            "T1003"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            yield return new BooleanConfig("Credential Guard", IsCredentialGuardEnabled());
        }

        private static bool IsCredentialGuardEnabled()
        {
            string regPath = @"System\CurrentControlSet\Control\DeviceGuard";
            if (Helper.GetRegValue("HKLM", regPath, "EnableVirtualizationBasedSecurity") != "1")
                return false;
            string regValue = Helper.GetRegValue("HKLM", regPath, "RequirePlatformSecurityFeatures");
            if (regValue != "1" && regValue != "3")
            {
                return false;
            }
            regValue = Helper.GetRegValue("HKLM", @"System\CurrentControlSet\Control\LSA", "LsaCfgFlags");
            if (regValue != "1" || regValue != "2")
            {
                return false;
            }
            return true;
        }
    }
}
