using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class DisabledFeature : EnumerationResults
    {
        bool FeatureDisabled;
        public DisabledFeature(string Info, bool IsDisabled)
        {
            this.Info = Info;
            FeatureDisabled = IsDisabled;
        }
        public override string ToString()
        {
            return FeatureDisabled? $"{Info} is disabled" : $"{Info} is not disabled";
        }

        public override ResultType ToResultType()
        {
            return FeatureDisabled ? ResultType.True : ResultType.False;
        }

    }
}
