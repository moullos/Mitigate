using Mitigate.Enumerations;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Mitigate.Utils
{
    public static class TrackerGeneration
    {
        public static void CreateTracker(IEnumerable<Enumeration> AllEnumerations, AttackCTI Attack, string Filename)
        {
            // Checking if all mitigations types defined in enumerations are defined in attack
            // Get all mitigation types
            var MitigationTypes = Attack.GetAllMitigationTypes();

            using (var tw = new StreamWriter(Filename))
            {
                tw.WriteLine("| Enumeration Class | Enumeration Description| Mitigation Description | Techniques Addressed |Mitigation Type");
                tw.WriteLine("| --- | --- | --- | --- | --- |");

                foreach (var mitigationType in MitigationTypes)
                {
                    // Get all implementated enumerations per mitigation type
                    var MitigationTypeEnumerations = AllEnumerations.Where(o => o.MitigationType == mitigationType);
                    
                    // Get all the techniques that can be mitigated by this mitigation type.
                    // Returns a dictionary with the description of the mitigation as a key and a list of the techniques addresses as values
                    var TechniquesMitigatedByMitigation = Attack.GetTechniquesAddressedbyMitigationType(mitigationType);
                    
                    //Figure out if the mitigation for the technique is implemented
                    foreach (var test in TechniquesMitigatedByMitigation)
                    {
                        var MitigationDescription = test.Key;
                        var TechniquesAddressed = test.Value;
                        // Is there an enumeration of this mitigation type for this techniques?
                        var EnumerationsAddressingThis = MitigationTypeEnumerations.Where(o => TechniquesAddressed.All(y=>o.Techniques.Contains(y)));
                        if (EnumerationsAddressingThis.Count() == 0)
                        {
                            tw.WriteLine($"|NA|NA|{MitigationDescription.Replace("\n", "").Replace("\r", "")} | {String.Join(", ", TechniquesAddressed)}|{mitigationType}");
                        }
                        else if (EnumerationsAddressingThis.Count() == 1)
                        {
                            tw.WriteLine($"{EnumerationsAddressingThis.First().GetType().Name + ".cs"}| {EnumerationsAddressingThis.First().EnumerationDescription}|{MitigationDescription.Replace("\n", "").Replace("\r", "")} |{String.Join(", ", TechniquesAddressed)}|{mitigationType}");
                        } 
                        else
                        {
                            tw.WriteLine($"{String.Join(",", EnumerationsAddressingThis.Select(o => o.GetType().Name + ".cs"))}|{String.Join(",", EnumerationsAddressingThis.Select(o => o.EnumerationDescription))}|{MitigationDescription.Replace("\n", "").Replace("\r", "")} |{String.Join(", ", TechniquesAddressed)}|{mitigationType}");
                        }
                    }
                }
            }
        }
    }
}
