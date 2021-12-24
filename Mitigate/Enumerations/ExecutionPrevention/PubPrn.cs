using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations
{
    class PubPrn : Enumeration
    {
        public override string Name => "PubPrn.vbs block";
        public override string MitigationType => MitigationTypes.ExecutionPrevention;
        public override string MitigationDescription => "Certain signed scripts that can be used to execute other programs may not be necessary within a given environment. Use application control configured to block execution of these scripts if they are not required for a given system or network to prevent potential misuse by adversaries.";
                public override string EnumerationDescription => "Checks for SRP or AppLocker restrictions on PubPrn.vbs";

        public override string[] Techniques => new string[] {
            "T1216.001",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var ExecName = "PubPrn.vbs";

            DirectoryInfo directory = new DirectoryInfo(@"C:\Windows\System32\Printing_Admin_Scripts");
            DirectoryInfo[] directories = directory.GetDirectories();

            foreach(var folder in directories)
            {
                var ExecPath = Path.Combine(folder.FullName, ExecName);
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
}
