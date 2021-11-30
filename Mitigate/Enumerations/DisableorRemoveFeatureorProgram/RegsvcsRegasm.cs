using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations.DisabldorRemoveFeatureorProgram
{
    class RegsvcsRegasm : Enumeration
    {
        public override string Name => "Regsvcs/Regasm Removed";
        public override string MitigationType => "Disable or Remove Feature or Program";
        public override string MitigationDescription => "Regsvcs and Regasm may not be necessary within a given environment.";
        public override string EnumerationDescription => "Checks if Regsvcs and Regasm are removed";

        public override string[] Techniques => new string[] {
            "T1218.009",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var DotNetPath = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
            
            bool IsRemoved = !File.Exists(Path.Combine(DotNetPath, "Regsvcs.exe"));
            yield return new RemovedFeature("Regsvcs.exe", IsRemoved);
            
            IsRemoved = !File.Exists(Path.Combine(DotNetPath, "Regasm.exe"));
            yield return new RemovedFeature("Regasm.exe", IsRemoved);
        }
    }
}
