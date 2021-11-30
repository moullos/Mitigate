using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisabldorRemoveFeatureorProgram
{
    class OfficeAddins : Enumeration
    {
        public override string Name => "Office Addins Restrictions";
        public override string MitigationType => "Disable or Remove Feature or Program";
        public override string MitigationDescription => "Disable Office add-ins. If they are required, follow best practices for securing them by requiring them to be signed and disabling user notification for allowing add-ins. For some add-ins types (WLL, VBA) additional mitigation is likely required as disabling add-ins in the Office Trust Center does not disable WLL nor does it prevent VBA code from executing.";
        public override string EnumerationDescription => "Checks if Office add-ins are disabled";

        public override string[] Techniques => new string[] {
            "T1137.001",
            "T1137",
            "T1221"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            foreach (var config in OfficeUtils.GetAddinsConf())
            {
                yield return new DisabledFeature(config.Key, config.Value);
            }
            yield return new DisabledFeature("Office VB", OfficeUtils.IsVBADisabled());

        }
    }
}
