using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class Failed : EnumerationResults
    {
        string EnumerationName { get; }
        string Message { get; }

        public Failed(string EnumerationName, string Message) 
        {
            this.EnumerationName = EnumerationName;
            this.Message = Message;
        }

        public override string ToString()
        {
            return $"{EnumerationName} enumeration has failed";
            //TODO maybe add an option for increased verbosity here
        }

        public override ResultType ToResultType()
        {
            return ResultType.TestFailed;
        }
    }
}
