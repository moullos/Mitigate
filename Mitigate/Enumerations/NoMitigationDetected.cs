using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class NoMitigationDetected : EnumerationResults
    {
        string Name { get; }

        public NoMitigationDetected(string Name)
        {
            this.Name = Name;
        }

        public override ResultType ToResultType()
        {
            return ResultType.False;
        }

        public override string ToString()
        {
            return $"{Name} was not detected";
        }
    }


}
