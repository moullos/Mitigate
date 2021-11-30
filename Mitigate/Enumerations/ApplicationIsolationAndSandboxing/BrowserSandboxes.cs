using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.ApplicationIsolationAndSandboxing
{
    class BrowserSandboxes : Enumeration
    {
        public override string Name => "Browser sandboxes";
        public override string MitigationType => "Application Isolation and Sandboxing";
        public override string EnumerationDescription => "List installed browsers and checks their sandboxing status";

        public override string MitigationDescription => "Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist.";
        public override string[] Techniques => new string[] {
            "T1189",
            "T1203"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // TODO:
            // Search for common browsers and check that their version supports sandboxing
            yield return new NotImplemented();

        }

    } 
}
