using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisabldorRemoveFeatureorProgram
{
    class VisualBasic : Enumeration
    {
        public override string Name => "Visual Basic Restrictions";
        public override string MitigationType => "Disable or Remove Feature or Program";
        public override string MitigationDescription => "Turn off or restrict access to unneeded VB components.";
        public override string EnumerationDescription => "Checks if VBA is disabled for office";

        public override string[] Techniques => new string[] {
            "T1059.005",
            "T1564.007"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            yield return new DisabledFeature("Office VB", OfficeUtils.IsVBADisabled());
            yield return new DisabledFeature("Outlook VB", OfficeUtils.IsVBBlockedOutlook());
        }
    }
}
