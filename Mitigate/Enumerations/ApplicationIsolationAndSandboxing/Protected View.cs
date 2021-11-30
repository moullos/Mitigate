using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.ApplicationIsolationAndSandboxing
{
    class ProtectedView : Enumeration
    {
        public override string Name => "Protected View";
        public override string MitigationType => "Application Isolation and Sandboxing";
        public override string MitigationDescription => "Ensure Office Protected View is enabled.";
        public override string EnumerationDescription => "Protected view status";

        public override string[] Techniques => new string[] {
            "T1559",
            "T1559.001",
            "T1559.002",
            "T1559.002",
            "T1021.003"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            foreach (var config in OfficeUtils.GetProtectedViewInfo())
            {
                var ConfigInfo = config.Key;
                var Result = config.Value;
                yield return new BooleanConfig(ConfigInfo, Result);
            }
        }

    }
}
