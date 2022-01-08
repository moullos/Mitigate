using Mitigate.Utils;
using System.Collections.Generic;

namespace Mitigate.Enumerations
{
    class RestrictWinRM : Enumeration
    {
        public override string Name => "Enforce whitelist for WinRM";
        public override string MitigationType => MitigationTypes.NetworkSegmentation;
        public override string MitigationDescription => @"If the service is necessary, lock down critical enclaves with separate WinRM infrastructure and follow WinRM best practices on use of host firewalls to restrict WinRM access to allow communication only to/from specific devices.";
        public override string EnumerationDescription => "Checks for restrictions on winRM via GPO";

        public override string[] Techniques => new string[] {
            "T1021",
            "T1021.006"
        };

        public override IEnumerable<EnumerationResults> Enumerate(Context context)
        {
            // Is winRM enabled?
            if (!IsWinRMDisabled())
            {
                if (IsWinrmGPODefined())
                {
                    string RegPath = @"Software\Policies\Microsoft\Windows\WinRM\Service";
                    var IPv4Filter = Helper.GetRegValue("HKLM", RegPath, "IPv4Filter");
                    yield return new ConfigurationDetected("WinRM traffic is restricted", IPv4Filter, IPv4Filter != "*" ? true : false);
                }
                else yield return new BooleanConfig("WinRM traffic restricted via GPO", false);
            }
            else yield return new NotApplicable("WinRM is not enabled on the device");
        }

        private bool IsWinRMDisabled()
        {
            var ServiceConfig = Helper.GetServiceConfig("WinRM");
            return ServiceConfig["StartUpType"] != "AUTOMATIC";
        }

        private static bool IsWinrmGPODefined()
        {
            string RegPath = @"Software\Policies\Microsoft\Windows\WinRM\Service";
            string RegKey = "AllowAutoConfig";

            return Helper.GetRegValue("HKLM", RegPath, RegKey) == "1" ? true : false;
        }
    }
}
