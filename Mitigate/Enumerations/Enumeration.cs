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
        public List<EnumerationResults> Results { get; set; }

        public void Execute(Context Context)
        {
            PrintUtils.EnumStart(this);
            try
            {
                Results = Enumerate(Context).ToList();
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

        private List<EnumerationResults> FailedTest(string EnumerationName, string Message)
        {
            var Results = new List<EnumerationResults>();
            Results.Add(new Failed(EnumerationName, Message));
            return Results;
        }

        private List<EnumerationResults> NoMitigationDetected()
        {
            var Results = new List<EnumerationResults>();
            Results.Add(new NoMitigationDetected(Name));
            return Results;
        }
    }
}

