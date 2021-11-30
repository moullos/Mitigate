using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class NotImplemented : EnumerationResults
    {
        public override string ToString()
        {
            return "Enumeration not implemented (yet!)";
        }

        public override ResultType ToResultType()
        {
            return ResultType.TestNotImplemented;
        }
    }
}
