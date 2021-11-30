using Mitigate.Utils;
using System.Collections.Generic;


namespace Mitigate.Enumerations.Antivirus
{
    class AMSI : Enumeration
    {
        public override string Name => "AMSI";
        public override string MitigationType => "Antivirus/Antimalware";
        public override string MitigationDescription => "Consider utilizing the Antimalware Scan Interface (AMSI) on Windows 10 to analyze commands after being processed/interpreted.";
        public override string EnumerationDescription => "Checks if any providers has been registered for AMSI";

        public override string[] Techniques => new string[] {
            "T1027"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            Helper.GetRegSubkeys("HKLM", @"SOFTWARE\Microsoft\AMSI\Providers");
            foreach (var provider in Helper.GetRegSubkeys("HKLM", @"SOFTWARE\Microsoft\AMSI\Providers"))
            {
                var providerDir =
                    Helper.GetRegValue("HKLM", $@"SOFTWARE\Classes\CLSID\{provider}", "");
                yield return new ToolDetected(providerDir);
            }
        }

    }
}
