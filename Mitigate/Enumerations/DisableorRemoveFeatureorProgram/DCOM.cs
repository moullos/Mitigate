using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class DCOM : Enumeration
    {
        public override string Name => "DCOM Disabled";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "Consider disabling DCOM through Dcomcnfg.exe.";
        public override string EnumerationDescription => "Checks if DCOM is disabled";

        public override string[] Techniques => new string[] {
            "T1021.003",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            yield return new DisabledFeature("DCOM", IsDCOMDisabled());
        }
        private static bool IsDCOMDisabled()
        {
            var RegPath = @"Software\Microsoft\OLE";
            var RegName = "EnableDCOM";

            return Helper.GetRegValue("HKLM", RegPath, RegName) == "N" ? true : false;
        }
    }
}
