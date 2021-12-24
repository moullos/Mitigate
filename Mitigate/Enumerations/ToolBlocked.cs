using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class ToolBlocked : EnumerationResults
    {
        readonly string Tool;
        readonly bool IsBlocked;
        readonly string Control;

        public ToolBlocked(string Tool, bool IsBlocked, string Control)
        {
            this.Tool = Tool;
            this.IsBlocked = IsBlocked;
            this.Control = Control;
        }

        public override string ToString()
        {
            return IsBlocked ? $"{Tool} is blocked by {Control}" : $"{Tool} is not blocked";
        }

        public override ResultType ToResultType()
        {
            return IsBlocked ? ResultType.True : ResultType.False;
        }

    }
}
