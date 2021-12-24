using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations
{
    class SoftwareRestrictionPolicies : Enumeration
    {
        public override string Name => "Software Restriction Policies";
        public override string MitigationType => MitigationTypes.CodeSigning;
        public override string MitigationDescription => "Require signed binaries";
        public override string EnumerationDescription => "Checks if and Software Restriction Policies enforce signed binaries";

        public override string[] Techniques => new string[] {
            "T1036.001",
            "T1036.005"
        };


        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var ConfigSet = SoftwareRestrictionUtils.CertificateRulesEnabled();
            yield return new BooleanConfig("Software Restriction Certificate Rules", ConfigSet);
        }
    }
}
