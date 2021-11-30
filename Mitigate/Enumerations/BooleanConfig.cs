using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class BooleanConfig : EnumerationResults
    {

        bool GoodConfigSet;
        public BooleanConfig(string Info, bool Result)
        {
            this.Info = Info;
            GoodConfigSet = Result;
        }
        public override string ToString()
        {
            return GoodConfigSet? $"{Info} is set" : $"{Info} is not set";
        }

        public override ResultType ToResultType()
        {
            return GoodConfigSet ? ResultType.True : ResultType.False;
        }

    }
}
