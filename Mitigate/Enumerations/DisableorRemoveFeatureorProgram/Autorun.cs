using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisabldorRemoveFeatureorProgram
{
  
    class Autorun : Enumeration
    {
        public override string Name => "Autorun disabled";
        public override string MitigationType => "Disable or Remove Feature or Program";
        public override string MitigationDescription => "Disable Autorun if it is unnecessary.";
        public override string EnumerationDescription => "Check if Autorun is disabled";

        public override string[] Techniques => new string[] {
            "T1092",
            "T1052",
            "T1052.001",
            "T1091"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            yield return new DisabledFeature("Autorun", IsAutorunDisabled());
        }

        private static bool IsAutorunDisabled()
        {
            var RegPath = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
            var RegName = "NoDriveTypeAutoRun";
            if (Helper.RegExists("HKLM", RegPath, RegName))
            {
                var Value = Helper.GetRegValue("HKLM", RegPath, RegName);
                if (Value == "181" || Value == "255") return true;
            }
            if (Helper.RegExists("HKCU", RegPath, RegName))
            {
                var Value = Helper.GetRegValue("HKCU", RegPath, RegName);
                if (Value == "181" || Value == "255") return true;
            }
            return false;
        }
    }
}
