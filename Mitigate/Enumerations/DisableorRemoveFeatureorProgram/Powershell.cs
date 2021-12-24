using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;


namespace Mitigate.Enumerations
{
    class PowerShell : Enumeration
    {
        public override string Name => "Powershell Restrictions";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "It may be possible to remove PowerShell from systems when not needed, but a review should be performed to assess the impact to an environment, since it could be in use for many legitimate purposes and administrative functions.";
        public override string EnumerationDescription => "Checks for SRP policies on Powershell";

        public override string[] Techniques => new string[] {
            "T1059.001"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            foreach(var restriction in GetPSRestrictions(context))
            {
                yield return new BooleanConfig(restriction.Key + " SRP / Applocker restriction", restriction.Value);
            }

        }

        private Dictionary<string, bool> GetPSRestrictions(Context context)
        {
            var PowerShellRestriction = new Dictionary<string, bool>();
            //x64
            var SystemPath64 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var PSPath64 = Path.Combine(SystemPath64, "WindowsPowerShell","v1.0","powershell.exe");
            var PSISEPath64 = Path.Combine(SystemPath64, "WindowsPowerShell","v1.0","powershell_ise.exe");
            PowerShellRestriction["Powershell 64bit"] = Helper.CheckForRestrictions(PSPath64, context.UserToCheck.SamAccountName);
            PowerShellRestriction["Powershell ISE 64bit"] = Helper.CheckForRestrictions(PSISEPath64, context.UserToCheck.SamAccountName);

            //x86
            var SystemPath86 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
            var PSPath86 = Path.Combine(SystemPath86, "WindowsPowerShell","v1.0","powershell.exe");
            var PSISEPath86 = Path.Combine(SystemPath86, "WindowsPowerShell","v1.0","powershell_ise.exe");

            PowerShellRestriction["Powershell 32bit"] = Helper.CheckForRestrictions(PSPath86, context.UserToCheck.SamAccountName);
            PowerShellRestriction["Powershell ISE 32bit"] = Helper.CheckForRestrictions(PSISEPath86, context.UserToCheck.SamAccountName);
            return PowerShellRestriction;
        }
    }
}
