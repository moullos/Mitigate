using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisabldorRemoveFeatureorProgram
{
    class WinRM : Enumeration
    {
        public override string Name => "WinRM Disabled";
        public override string MitigationType => "Disable or Remove Feature or Program";
        public override string MitigationDescription => "Disable the WinRM service.";
        public override string EnumerationDescription => "Checks if WinRM is disabled";


        public override string[] Techniques => new string[] {
            "T1021.006",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            yield return new DisabledFeature("WinRM", IsWinRMDisabled());
        }
        private bool IsWinRMDisabled()
        {
            var ServiceConfig = Helper.GetServiceConfig("WinRM");
            return ServiceConfig["StartUpType"] != "AUTOMATIC";

        }
    }
}
