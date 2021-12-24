using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations
{
    class RegasmRegsvcs : Enumeration
    {
        public override string Name => "Regasm.exe and/or Regsvcs block";
        public override string MitigationType => MitigationTypes.ExecutionPrevention;
        public override string MitigationDescription => "Block execution of Regsvcs.exe and Regasm.exe if they are not required for a given system or network to prevent potential misuse by adversaries.";
        public override string EnumerationDescription => "Checks for SRP or AppLocker restrictions on Regasm.exe and/or REgsvcs.exe";

        public override string[] Techniques => new string[] {
            "T1218.009",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var ExecName = "Regasm.exe";
            var DotNetPath = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
            var ExecPath = Path.Combine(DotNetPath, ExecName);
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

            ExecName = "Regsvcs.exe";
            ExecPath = Path.Combine(DotNetPath, ExecName);
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
