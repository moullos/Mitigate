using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisabledorRemoveFeatureorProgram
{
    class ScreenSavers : Enumeration
    {
        public override string Name => "ScreenSaver disabled";
        public override string MitigationType => "Disable or Remove Feature or Program";
        public override string MitigationDescription => "Use Group Policy to disable screensavers if they are unnecessary.";
        public override string EnumerationDescription => "Checks if ScreenSavers are disabled";

        public override string[] Techniques => new string[] {
            "T1546.002"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            yield return new DisabledFeature("Screen Saver", IsScreenSaverDisabled());
        }

        private static bool IsScreenSaverDisabled()
        {
            return Helper.GetRegValue("HKLM", @"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveActive") == "0";
        }
    }
}
