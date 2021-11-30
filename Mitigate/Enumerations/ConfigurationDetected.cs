using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Mitigate.Enumerations
{
    class ConfigurationDetected : EnumerationResults
    {
        string value;
        bool result;
        string condition;
        public ConfigurationDetected(string ConfigurationName, string value, bool result = true, string condition = null)
        {
            this.Info = ConfigurationName;
            this.value = value;
            this.result = result;
            this.condition = condition;
        }

        public override string ToString()
        {
            if (result)
                return $"{Info} was set to {value}";
            else
                return $"{Info} was set to {value}. Expected value was {condition}";
        }

        public override ResultType ToResultType()
        {
            return result ? ResultType.True : ResultType.False;
        }

    }
}
