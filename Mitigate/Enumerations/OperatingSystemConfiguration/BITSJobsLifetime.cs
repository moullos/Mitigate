using Mitigate.Utils;
using System;
using System.Collections.Generic;

namespace Mitigate.Enumerations.OperatingSystemConfiguration
{
    class BITSJobsLifetimeLimit : Enumeration
    {
        public override string Name => "Bits Jobs Lifetime Limit";
        public override string MitigationType => "Operating System Configuration";
        public override string MitigationDescription => @"Consider reducing the default BITS job lifetime in Group Policy or by editing the JobInactivityTimeout and MaxDownloadTime Registry values in HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS.";
        public override string EnumerationDescription => "Checks if the BITS job configuration is in line with the CIS benchmarks";

        public override string[] Techniques => new string[] {
            "T1197",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var JobInactivityTimeout = Helper.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\BITS", "JobInactivityTimeout");
            if (int.TryParse(JobInactivityTimeout, out int JobInactivityTimeoutInt))
            {
                yield return new ConfigurationDetected("Job Inactivity Timeout", JobInactivityTimeout, JobInactivityTimeoutInt < 90);
            }
            else yield return new ConfigurationDetected("Job Inactivity Timeout", "Default", false);

            var MaxDownloadTime = Helper.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\BITS", "MaxDownloadTime");
            if (int.TryParse(MaxDownloadTime, out int MaxDownloadTimeInt))
            {
                yield return new ConfigurationDetected("Max Download Time", MaxDownloadTime, MaxDownloadTimeInt < 54000);
            }
            else yield return new ConfigurationDetected("Max Download Time", "Default", false);
        }
    }
}
