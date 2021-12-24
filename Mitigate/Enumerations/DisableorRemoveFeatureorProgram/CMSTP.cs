using System;
using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations.DisabldorRemoveFeatureorProgram
{
  
    class CMSTP : Enumeration
    {
        public override string Name => "CMSTP Removed";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "CMSTP.exe may not be necessary within a given environment (unless using it for VPN connection installation).";
        public override string EnumerationDescription => "Checks if CMSTP is removed";

        public override string[] Techniques => new string[] {
            "T1218.003",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var System32Dir = Environment.SystemDirectory;
            bool IsRemoved = !File.Exists(Path.Combine(System32Dir, "CMSTP.exe"));
            yield return new RemovedFeature("CMSTP.exe", IsRemoved);
        }
    }
}
