using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations.OperatingSystemConfiguration
{
    class RootCertAdmin : Enumeration
    {
        public override string Name => "Adding new root certificates requires administrative access";
        public override string MitigationType => "Operating System Configuration";
        public override string MitigationDescription => @"Windows Group Policy can be used to manage root certificates and the Flags value of HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots can be set to 1 to prevent non-administrator users from making further root installations into their own HKCU certificate store.";
        public override string EnumerationDescription => "Checks if the addition of new root certificates requires elevated privileges";

        public override string[] Techniques => new string[] {
            "T1553.004"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {


            var RegValue = Helper.GetRegValue("HKLM", @"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots", "Flags");
            yield return new BooleanConfig("Admin permissions required for adding new root certs", RegValue == "1");
        }
    }
}
