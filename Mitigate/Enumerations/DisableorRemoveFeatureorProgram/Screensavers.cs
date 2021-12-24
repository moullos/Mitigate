using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations
{
    class ScreenSavers : Enumeration
    {
        public override string Name => "ScreenSaver disabled";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
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
