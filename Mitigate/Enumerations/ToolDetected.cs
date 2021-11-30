using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    public class ToolDetected : EnumerationResults
    {
        public ToolDetected(string ToolName)
        {
            this.Info = ToolName;
        }

        public override string ToString()
        {
            return $"{Info} was detected";
        }

        public override ResultType ToResultType()
        {
            return ResultType.True;
        }
    }
}
