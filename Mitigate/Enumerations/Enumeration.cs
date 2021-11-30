using Mitigate.Utils;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Mitigate.Enumerations
{
    public abstract class Enumeration
    {
        public abstract string Name { get; }
        public abstract string MitigationDescription { get; }
        public abstract string MitigationType { get; }
        public abstract string EnumerationDescription { get; }
        public abstract string[] Techniques { get; }
        public IEnumerable<EnumerationResults> Results { get; set; }

        public void Execute(Context Context)
        {
            PrintUtils.EnumStart(this);
            try
            {
                Results = Enumerate(Context);
                if (!Results.Any())
                {
                    Results = NoMitigationDetected();
                }
                PrintResults(Results);
            }
            catch (Exception ex)
            {
                Results = FailedTest(Name, ex.Message);
                PrintResults(Results);
                if (Context.Arguments.Debug)
                {
                    Console.WriteLine(ex.Message);
                    Console.WriteLine(ex.StackTrace);
                }
            }
        }

        public abstract IEnumerable<EnumerationResults> Enumerate(Context context);

        public void PrintResults(IEnumerable<EnumerationResults> Results)
        {
            if (Results == null || !Results.Any())
            {
                throw new ArgumentNullException();
            }

            foreach (var item in Results)
            {
                PrintUtils.PrintResultSymbol(item.ToResultType());
                Console.WriteLine(item.ToString());
            }

        }

        private IEnumerable<EnumerationResults> FailedTest(string EnumerationName, string Message)
        {
            yield return new Failed(EnumerationName, Message);
        }

        private IEnumerable<EnumerationResults> NoMitigationDetected()
        {
            yield return new NoMitigationDetected(Name);
        }
    }
}

