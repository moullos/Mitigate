using System;
using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations
{ 
  
    class MSHTA : Enumeration
    {
        public override string Name => "MSHTA Removed";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "Mshta.exe may not be necessary within a given environment since its functionality is tied to older versions of Internet Explorer that have reached end of life.";
        public override string EnumerationDescription => "Checks if Mshta is removed";

        public override string[] Techniques => new string[] {
            "T1218.005",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var System32Dir = Environment.SystemDirectory;
            bool IsRemoved = !File.Exists(Path.Combine(System32Dir, "mshta.exe"));
            yield return new RemovedFeature("mshta.exe", IsRemoved);
        }
    }
}
