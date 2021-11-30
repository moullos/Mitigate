using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations.NoMitigation
{
    class NoMitigation : Enumeration
    {
        public override string Name => "No Mitigation Available";
        public override string MitigationType => "No Mitigation Available";
        public override string MitigationDescription => "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features";
        public override string EnumerationDescription => "Dummy enumeration to populate the navigator for techniques which cannot be mitigated";

        public override string[] Techniques => new string[] {
            "T1531",
            "T1547.014",
            "T1560.003",
            "T1560.002",
            "T1027.001",
            "T1547",
            "T1553.002",
            "T1027.004",
            "T1546.015",
            "T1056.004",
            "T1568.003",
            "T1069.002",
            "T1087.003",
            "T1546",
            "T1568.001",
            "T1615",
            "T1027.006",
            "T1564.005",
            "T1564.001",
            "T1564",
            "T1546.012",
            "T1027.005",
            "T1056",
            "T1534",
            "T1016.001",
            "T1056.001",
            "T1074.001",
            "T1069.001",
            "T1036.004",
            "T1546.007",
            "T1134.004",
            "T1547.010",
            "T1620",
            "T1547.001",
            "T1074.002",
            "T1036.002",
            "T1518.001",
            "T1518",
            "T1027.003",
            "T1497.001",
            "T1497.001",
            "T1614.001",
            "T1614",
            "T1529",
            "T1497.003",
            "T1497.002",
            "T1497"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            yield return new NoMitigationAvailable();
        }   
    }
}
