using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations.ExecutionPrevention
{
    class Mshta : Enumeration
    {
        public override string Name => "Mshta.exe block";
        public override string MitigationType => "Execution Prevention";
        public override string MitigationDescription => "Use application control configured to block execution of mshta.exe if it is not required for a given system or network to prevent potential misuse by adversaries.";
        public override string EnumerationDescription => "Checks for SRP or AppLocker restrictions on mshta.exe";
        public override string[] Techniques => new string[] {
            "T1218.005",
        };
        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var ExecName = "Mshta.exe";
            var System32Dir = Environment.SystemDirectory;
            var ExecPath = Path.Combine(System32Dir, ExecName);
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
