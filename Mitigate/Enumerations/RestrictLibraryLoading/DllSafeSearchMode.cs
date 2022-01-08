using Mitigate.Utils;
using System.Collections.Generic;
using System.Linq;

namespace Mitigate.Enumerations
{
    class DllSafeSearchMode : Enumeration
    {
        public override string Name => "DLL Safe Search Mode Enabled";
        public override string MitigationType => MitigationTypes.RestrictLibraryLoading;
        public override string MitigationDescription => @"Ensure safe DLL search mode is enabled HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode to mitigate risk that lsass.exe loads a malicious code library.";
        public override string EnumerationDescription => "Checks if DLL safe search mode is enabled";

        public override string[] Techniques => new string[] {
            "T1547.008",
            "T1574",
            "T1574.001"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            var RegPath = @"System\CurrentControlSet\Control\Session Manager";
            var RegKey = "SafeDllSearchMode ";
            var RegValue = Helper.GetRegValue("HKLM", RegPath, RegKey);
            
            yield return new BooleanConfig("DLL safe search", RegValue != "0");
        }
    }
}
