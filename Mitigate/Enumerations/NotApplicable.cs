using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class NotApplicable : EnumerationResults
    {
        public NotApplicable(string Info)
        {
            this.Info = Info;
        }
        public override string ToString()
        {
            return Info;
        }

        public override ResultType ToResultType()
        {
            return ResultType.NA;
        }
    }
}
