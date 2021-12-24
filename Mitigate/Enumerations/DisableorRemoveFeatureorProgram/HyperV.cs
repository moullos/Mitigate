using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations
{ 
  
    class HyperV : Enumeration
    {
        public override string Name => "Hyper Disabled";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "Disable Hyper-V if not necessary within a given environment.";
        public override string EnumerationDescription => "Checks if Hyper-V is disabled";

        public override string[] Techniques => new string[] {
            "T1564.006",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // TODO:
            // Check hyperv status
            yield return new NotImplemented();
        }
    }
}
