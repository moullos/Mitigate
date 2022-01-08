using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class GenericResult : EnumerationResults
    {
        bool Result;
        public GenericResult(string Info, bool result)
        {
            this.Info = Info;
            Result = result;
        }
        public override string ToString()
        {
            return Info;
        }

        public override ResultType ToResultType()
        {
            return Result ? ResultType.True : ResultType.False;
        }

    }
}
