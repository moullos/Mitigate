using Mitigate.Utils;
using System;
using System.Collections.Generic;

namespace Mitigate.Enumerations.OperatingSystemConfiguration
{
    class ScheduleTasksRunAs : Enumeration
    {
        public override string Name => "Scheduled tasks run do not run as SYSTEM";
        public override string MitigationType => "Operating System Configuration";
        public override string MitigationDescription => @"Configure settings for scheduled tasks to force tasks to run under the context of the authenticated account instead of allowing them to run as SYSTEM. The associated Registry key is located at HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SubmitControl. The setting can be configured through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > Security Options: Domain Controller: Allow server operators to schedule tasks, set to disabled.";
        public override string EnumerationDescription => "Checks if schedules tasks are not set to run as SYSTEM";

        public override string[] Techniques => new string[] {
            "T1053.002",
            "T1053.005"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RegValue = Helper.GetRegValue("HKML", @"SYSTEM\CurrentControlSet\Control\Lsa\", "SubmitControl");
            yield return new BooleanConfig("Scheduled tasks run as SYSTEM", RegValue == "0");
        }
    }
}
