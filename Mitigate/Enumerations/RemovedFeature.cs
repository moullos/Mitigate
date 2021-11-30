using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class RemovedFeature : EnumerationResults
    {
        bool FeatureRemoved;
        public RemovedFeature(string Info, bool IsRemoved)
        {
            this.Info = Info;
            FeatureRemoved = IsRemoved;
        }
        public override string ToString()
        {
            return FeatureRemoved ? $"{Info} is removed" : $"{Info} is not removed";
        }

        public override ResultType ToResultType()
        {
            return FeatureRemoved ? ResultType.True : ResultType.False;
        }

    }
}
