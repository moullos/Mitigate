using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations
{
    class Odbcconf : Enumeration
    {
        public override string Name => "Odbcconf Removed";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "Regsvcs and Regasm may not be necessary within a given environment.";
        public override string EnumerationDescription => "Checks if odbcconf is removed";


        public override string[] Techniques => new string[] {
            "T1218.008",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var System32Dir = System.Environment.SystemDirectory;
            bool IsRemoved = !File.Exists(Path.Combine(System32Dir, "odbcconf.exe"));
            yield return new RemovedFeature("Odbcconf.exe", IsRemoved);
        }

    }
}
