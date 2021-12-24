using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisableorRemoveFeatureorProgram
{
    class AlwaysInstallElevatedDisabled : Enumeration
    {
        public override string Name => "AlwaysInstallElevated disabled";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "Consider disabling the AlwaysInstallElevated policy to prevent elevated execution of Windows Installer packages.";
        public override string EnumerationDescription => "Checks if the AlwaysInstallElevated registry key is disabled";

        public override string[] Techniques => new string[] {
            "T1218.007"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // https://docs.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated
            var RegValue = Helper.GetRegValue("HKML", @"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated");
            yield return new DisabledFeature("AlwaysInstallElevated", RegValue != "1");
        }
    }
}
