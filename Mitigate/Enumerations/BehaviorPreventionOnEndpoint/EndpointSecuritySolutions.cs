using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.BehaviourPreventionOnEndpoint
{
    class EndpointSecuritySolutions : Enumeration
    {
        public override string Name => "Endpoint Security Solutions";
        public override string MitigationType => "Behavior Prevention on Endpoint";
        public override string MitigationDescription => "Some endpoint security solutions can be configured to block some types of process injection based on common sequences of behavior that occur during the injection process.";
        public override string EnumerationDescription => "TODO";

        public override string[] Techniques => new string[] {
            "T1189",
            "T1203"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // TODO:
            // Search for common EDRs
            yield return new NotImplemented();

        }

    }
}
