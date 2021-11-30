using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisabldorRemoveFeatureorProgram
{
    class RDP : Enumeration
    {
        public override string Name => "RDP Disabled";
        public override string MitigationType => "Disable or Remove Feature or Program";
        public override string MitigationDescription => "Disable the RDP service if it is unnecessary.";
        public override string EnumerationDescription => "Checks if RDP is disabled";


        public override string[] Techniques => new string[] {
            "T1563",
            "T1563.002",
            "T1021.001"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            yield return new DisabledFeature("RDP", IsRDPDisabled());
        }

        private static bool IsRDPDisabled()
        {
            var RegPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
            var RegName = "fDenyTSConnections";

            return Helper.GetRegValue("HKLM", RegPath, RegName) == "1" ? true : false;
        }
    }
}
