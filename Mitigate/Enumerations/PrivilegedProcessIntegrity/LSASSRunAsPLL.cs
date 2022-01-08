using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class LSASSRunAsPLL : Enumeration
    {
        public override string Name => "Enable Protected Process Light(PLL), for LSA";
        public override string MitigationType => MitigationTypes.PrivilegedProcessIntegrity;
        public override string MitigationDescription => "Enabled features, such as Protected Process Light (PPL), for LSA";
        public override string EnumerationDescription => "Checks if Protected Process Light for LSA is enabled";

        public override string[] Techniques => new string[] {
            "T1547.002",
            "T1547.005",
            "T1547.008",
            "T1556",
            "T1556.001",
            "T1003",
            "T1003.001"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            string RunAsPPL = Helper.GetRegValue("HKLM", @"System\CurrentControlSet\Control\Lsa", "RunAsPPL");
            yield return new BooleanConfig("Protected Process Light for LSA", RunAsPPL == "1");
        }
    }
}
