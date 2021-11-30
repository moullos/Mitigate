using Mitigate.Utils;
using System;
using System.Collections.Generic;

namespace Mitigate.Enumerations.ExecutionPrevention
{
    class UnknownDLLs : Enumeration
    {
        public override string Name => "Prevent Execution of Unknown DLLs";
        public override string MitigationType => "Execution Prevention";
        public override string MitigationDescription => "Identify and block potentially malicious software by using application control tools like Windows Defender Application Control, AppLocker, or Software Restriction Policies [6 that are capable of auditing and/or blocking unknown DLLs.";
        public override string EnumerationDescription => "Checks if SRPs or Applocker is enabled for DLLs";

        public override string[] Techniques => new string[] {
            "T1547.004",
            "T1546.009",
            "T1546.010",
            "T1574",
            "T1574.001",
            "T1574.006",
            "T1574.012",
            "T1129",
            "T1553.003",


        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // Checking for restriction on unknown DLLs
            // 1. Check for AppLocker
            // 2. if not set then chech for Software Restriction Policies
            // 3. Check for ASR rules
            if (AppLockerUtils.IsAppLockerEnabled("DLL"))
            {
                if (!AppLockerUtils.IsAppLockerRunning())
                {
                    throw new Exception("AppLocker SVC is not running");
                }
                yield return new BooleanConfig("App Locker DLL Rules", true);
                var Rules = AppLockerUtils.GetAppLockerRules("DLL");
                foreach (var rule in Rules)
                {
                    yield return new ConfigurationDetected(rule.Name, rule.Action);
                }
            }
            else if (SoftwareRestrictionUtils.DLLMonitoringEnabled())
            {
                yield return new BooleanConfig("SRP DLL monitoring", true);
            }
            // WDAC
        }

    }
}
