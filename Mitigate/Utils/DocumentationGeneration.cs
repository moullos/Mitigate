using Mitigate.Enumerations;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Mitigate.Utils
{
    public static class DocumentationGeneration
    {
        public static void CreateEnumerationCoveragePerMitigationType(IEnumerable<Enumeration> AllEnumerations, AttackCTI Attack, string Filename)
        {
            // Checking if all mitigations types defined in enumerations are defined in attack
            var AllMitigationTypes = AllEnumerations.
                            Select(o => o.MitigationType).
                            Distinct();

            var AllMitigationTypesAttack = Attack.GetAllMitigationTypes();

            foreach (var mitigationType in AllMitigationTypes)
            {
                if (mitigationType==MitigationTypes.NoMitigationAvailable)
                        continue;
                if (!AllMitigationTypesAttack.Contains(mitigationType))
                {
                    throw new Exception($"{mitigationType} is not an Att&ck-defined enumeration type");
                }
            }


            using (var tw = new StreamWriter(Filename))
            {
                foreach (var mitigationType in AllMitigationTypesAttack) 
                {
                    tw.WriteLine(MarkdownHeader(mitigationType));
                    
                    // Get all implementated enumerations per mitigation type
                    var MitigationTypeEnumerations = AllEnumerations.Where(o => o.MitigationType == mitigationType);

                    if (MitigationTypeEnumerations.Count() > 1)
                    {
                        tw.WriteLine("|Mitigation Description | Enumeration Details | Enumeration Class | Techniques Covered |");
                        tw.WriteLine("|---|---|---|---|");


                        foreach (var enumeration in MitigationTypeEnumerations)
                        {
                            tw.WriteLine($"|{enumeration.MitigationDescription}|{enumeration.EnumerationDescription}|{enumeration.GetType().Name + ".cs"}|{string.Join(", ", enumeration.Techniques)}|");
                        }
                    }
                    else
                    {
                        tw.WriteLine("No enumerations defined for the mitigation yet");
                    }

                }            


            }
            
        }

        private static string MarkdownHeader(string mitigationType)
        {
            return "### " + mitigationType;
        }

        private static string MarkdownBullet(string mitigationName, string mitigationDescription)
        {
            return "- " + mitigationName + ": " + mitigationDescription;
        }

    }
}
