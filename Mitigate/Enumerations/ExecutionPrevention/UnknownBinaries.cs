using Mitigate.Utils;
using System;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class UnknownBinaries : Enumeration
    {
        public override string Name => "Prevent Execution of Unknown Binaries";
        public override string MitigationType => MitigationTypes.ExecutionPrevention;
        public override string MitigationDescription => " Identify and block potentially malicious software executed through accessibility features functionality by using application control tools, like Windows Defender Application Control, AppLocker, or Software Restriction Policies where appropriate.";
        public override string EnumerationDescription => "Checks for SRP or AppLocker restrictions on unknown binaries";

        public override string[] Techniques => new string[] {
            "T1548",
            "T1546.006",
            "T1546.008",
            "T1574.007",
            "T1574.008",
            "T1574.009",
            "T1106",
            "T1219",
            "T1218",
            "T1080",
            "T1204",
            "T1204.002",


        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // Checking for restriction on unknown executables
            var AppLocker = AppLockerUtils.IsAppLockerEnabled("Executable Rules");
            var SRPs = SoftwareRestrictionUtils.IsEnabled();


            // 1. Check for AppLocker
            if (AppLockerUtils.IsAppLockerEnabled("Executable Rules"))
            {
                if (!AppLockerUtils.IsAppLockerRunning())
                {
                    throw new Exception("AppLocker service is not running");
                }
                yield return new BooleanConfig("App Locker Executable Rules", AppLocker);
                
                if (context.Arguments.Full)
                {
                    var Rules = AppLockerUtils.GetAppLockerRules("Executable rules");
                    foreach (var rule in Rules)
                    {
                        yield return new ConfigurationDetected(rule.Name, rule.Action);
                    }
                }
                yield break;
            }
            // 2. if not set then check for Software Restriction Policies
            yield return new BooleanConfig("SRP Restriction on executables", SoftwareRestrictionUtils.IsEnabled());
            if (context.Arguments.Full)
            {
                // TODO: Check if all the expected extensions are covered
            }
        }

    }
}
