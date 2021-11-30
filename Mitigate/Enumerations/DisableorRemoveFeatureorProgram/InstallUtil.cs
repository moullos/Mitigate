using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Mitigate.Enumerations.DisabledorRemoveFeatureorProgram
{
  
    class InstallUtil : Enumeration
    {
        public override string Name => "InstallUtil Removed";
        public override string MitigationType => "Disable or Remove Feature or Program";
        public override string MitigationDescription => "InstallUtil may not be necessary within a given environment.";
        public override string EnumerationDescription => "Checks if InstallUtil is removed";

        public override string[] Techniques => new string[] {
            "T1218.004",
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var DotNetPath = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
            bool IsRemoved = !File.Exists(Path.Combine(DotNetPath, "InstallUtil.exe"));
            yield return new RemovedFeature("InstallUtil.exe", IsRemoved);
        }
    }
}
