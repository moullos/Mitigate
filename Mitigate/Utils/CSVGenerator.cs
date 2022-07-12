using Mitigate.Enumerations;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Mitigate.Utils
{
    public static class CSVGenerator
    {
        public static void WriteCSV(IEnumerable<Enumeration> AllEnumerations, string Filename, char Delimeter)
        {
            // want to keep dependencies to a minimum so no CSVHelper
            var csv = new StringBuilder();
            csv.AppendLine($"Enumeration Description{Delimeter}Findings{Delimeter}Result{Delimeter}Mitigation Description{Delimeter}Mitigation Type{Delimeter}Relevant Techniques");
            foreach (Enumeration e in AllEnumerations)
            {
                foreach (var r in e.Results)
                {
                    csv.AppendLine($"{e.EnumerationDescription}{Delimeter}{r}{Delimeter}{r.ToResultType()}{Delimeter}{e.MitigationDescription}{Delimeter}{e.MitigationType}{Delimeter}{string.Join(",",e.Techniques)}");

                }
            }
            using (var tw = new StreamWriter(Filename))
            {
                tw.Write(csv.ToString());
                tw.Close();
            }
        }
    }
}
