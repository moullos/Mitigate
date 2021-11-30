using System;

namespace Mitigate.Enumerations
{
    public abstract class EnumerationResults
    {
        public string Info { get; set; }

        public override string ToString() => throw new NotImplementedException();
        public abstract ResultType ToResultType();
    }
}
