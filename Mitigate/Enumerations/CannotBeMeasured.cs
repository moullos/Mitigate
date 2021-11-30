using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class CannotBeMeasured : EnumerationResults
    {
        string Name { get; }

        public CannotBeMeasured(string Name)
        {
            this.Name = Name;
        }

        public override ResultType ToResultType()
        {
            return ResultType.CannotBeMeasured;
        }

        public override string ToString()
        {
            return $"Cannot be measured and was only added to the results for completeness";
        }
    }


}
