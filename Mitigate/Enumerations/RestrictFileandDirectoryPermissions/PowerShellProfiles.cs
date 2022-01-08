using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations
{
    class PowerShellProfiles : Enumeration
    {
        public override string Name => "Make powershell profiles immutable from low privilege users";
        public override string MitigationType => MitigationTypes.RestrictFileAndDirectoryPermissions;
        public override string MitigationDescription => @"Making PowerShell profiles immutable and only changeable by certain administrators will limit the ability for adversaries to easily create user level persistence.";
        public override string EnumerationDescription => "Checks PS profile permissions";

        public override string[] Techniques => new string[] {
            "T1546",
            "T1546.013"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // from https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf
            var windir = Environment.SpecialFolder.Windows;
            var homedrive = Environment.GetEnvironmentVariable("HOMEDRIVE");
            var user = context.UserToCheck.SamAccountName;
            List<string> ProfilePaths = new List<string>()
                {

                    {$"{homedrive}\\{windir}\\System32\\WindowsPowerShell\\v1.0\\profile.ps1"},
                    {$"{homedrive}\\{windir}\\SysWOW64\\WindowsPowerShell\\v1.0\\profile.ps1"},
                    {$"{homedrive}\\{windir}\\System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1"},
                    {$"{homedrive}\\{windir}\\System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShellISE_profile.ps1"},
                    {$"{homedrive}\\{windir}\\SysWOW64\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1"},
                    {$"{homedrive}\\{windir}\\SysWOW64\\WindowsPowerShell\\v1.0\\Microsoft.PowerShellISE_profile.ps1"},
                };
            if (Directory.Exists($"{homedrive}\\Users\\{user}\\Documents"))
            {
                ProfilePaths.Add($"{homedrive}\\Users\\{user}\\Documents\\profile.ps1");
                ProfilePaths.Add($"{homedrive}\\Users\\{user}\\Documents\\Microsoft.PowerShell_profile.ps1");
                ProfilePaths.Add($"{homedrive}\\Users\\{user}\\Documents\\Microsoft.PowerShellISE_profile.ps1");
            }
            Dictionary<string, bool> ProfilePermissions = new Dictionary<string, bool>();
            foreach (var profilePath in ProfilePaths)
            {
                yield return new BooleanConfig($"Restricted {profilePath}", !Helper.FileWritePermissions(profilePath, context.UserToCheckSIDs));
            }
        }
    }
}
