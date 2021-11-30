using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.CodeSigning
{
    class SoftwareRestrictionPolicies : Enumeration
    {
        public override string Name => "Software Restriction Policies";
        public override string MitigationType => "Code Signing";
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
