using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisabldorRemoveFeatureorProgram
{
    class DCOM : Enumeration
    {
        public override string Name => "DCOM Disabled";
        public override string MitigationType => "Disable or Remove Feature or Program";
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
