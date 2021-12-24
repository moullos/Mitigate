using System.Collections.Generic;
using System.IO;

namespace Mitigate.Enumerations
{
    class MSbuild : Enumeration
    {
        public override string Name => "MSBuild Removed";
        public override string MitigationType => MitigationTypes.DisableOrRemoveFeatureOrProgram;
        public override string MitigationDescription => "MSBuild.exe may not be necessary within an environment and should be removed if not being used.";
        public override string EnumerationDescription => "Checks if MSBuild exists";


        public override string[] Techniques => new string[] {
            "T1127.001",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var DotNetPath = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
            bool IsRemoved = !File.Exists(Path.Combine(DotNetPath, "MSBuild.exe"));
            yield return new RemovedFeature("MSBuild.exe", IsRemoved);

        }
    }
}
