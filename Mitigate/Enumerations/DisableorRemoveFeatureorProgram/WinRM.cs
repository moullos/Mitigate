using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class WinRM : Enumeration
    {
        public override string Name => "WinRM Disabled";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
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
