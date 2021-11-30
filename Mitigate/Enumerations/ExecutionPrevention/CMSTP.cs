using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations.ExecutionPrevention
{
    class CSMTP : Enumeration
    {
        public override string Name => "CMSTP blocked";
        public override string MitigationType => "Execution Prevention";
        public override string MitigationDescription => "Consider using application control configured to block execution of CMSTP.exe if it is not required for a given system or network to prevent potential misuse by adversaries.";
        public override string EnumerationDescription => "Checks for SRP or AppLocker restrictions on CMSTP";

        public override string[] Techniques => new string[] {
            "T1218.003",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var System32Dir = Environment.SystemDirectory;
            var ExecName = "CMSTP.exe";
            var ExecPath = Path.Combine(System32Dir, "CMSTP.exe");
            if (!File.Exists(ExecPath))
            {
                PrintUtils.Debug($"File '{ExecPath}' was not found");
                yield return new RemovedFeature(ExecName, true);
                yield break;
            }
            // Check 1: AppLocker
            if (AppLockerUtils.IsAppLockerEnabled())
            {
                if (!AppLockerUtils.IsAppLockerRunning())
                {
                    throw new Exception("AppLocker SVC is not running");
                }
                if (AppLockerUtils.CheckApplockerPolicyforDenied(ExecPath, context.UserToCheck.DistinguishedName))
                {
                    yield return new ToolBlocked(ExecName, true, "AppLocker");
                }
            }
            else if (SoftwareRestrictionUtils.IsEnabled())
            {
                // SRPs are only applied if AppLocker is not active
                yield return new ToolBlocked(ExecName, SoftwareRestrictionUtils.IsBlocked(ExecPath), "Software Restriction Policy");
            }
        }
    }
}
