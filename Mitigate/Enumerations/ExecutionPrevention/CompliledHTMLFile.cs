using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations
{
    class CompiledHTMLFiles : Enumeration
    {
        public override string Name => "hh.exe blocked";
        public override string MitigationType => MitigationTypes.ExecutionPrevention;
        public override string MitigationDescription => "Consider using application control to prevent execution of hh.exe if it is not required for a given system or network to prevent potential misuse by adversaries.";
        public override string EnumerationDescription => "Checks for SRP or AppLocker restrictions on hh.exe";
        public override string[] Techniques => new string[] {
            "T1218.001",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var ExecName = "hh.exe";
            var ExecPath = Path.Combine(WindowsDir, ExecName);
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
