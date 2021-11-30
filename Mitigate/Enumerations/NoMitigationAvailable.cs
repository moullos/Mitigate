using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class NoMitigationAvailable : EnumerationResults
    {


        public override ResultType ToResultType()
        {
            return ResultType.NoMitigationAvailable;
        }

        public override string ToString()
        {
            return $"Techniques cannot be mitigated";
        }
    }


}
